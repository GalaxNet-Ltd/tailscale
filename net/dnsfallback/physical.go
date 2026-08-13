// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dnsfallback

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/netx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/logger"
)

const (
	bootstrapStageTimeout   = 3 * time.Second
	physicalDNSStageTimeout = 2 * time.Second
	physicalDNSUDPTimeout   = 1 * time.Second
	physicalDNSTCPTimeout   = 1 * time.Second
)

// physicalDNSServers are queried only after the existing DERP bootstrap DNS
// mechanism fails. They are literal addresses so using them never consults
// the potentially-poisoned system resolver.
var physicalDNSServers = []string{
	"1.1.1.1:53",
	"8.8.8.8:53",
	"9.9.9.9:53",
}

type lookupFunc func(context.Context, string) ([]netip.Addr, error)

// MakeLookupFuncWithPhysicalDNS is like MakeLookupFunc, with a final classic
// DNS fallback over the physical network. The existing DERP bootstrap lookup
// always runs first and is otherwise unchanged.
//
// Physical DNS tries UDP first and TCP after an error or timeout. The Go DNS
// resolver also retries a truncated UDP response over TCP automatically.
func MakeLookupFuncWithPhysicalDNS(logf logger.Logf, netMon *netmon.Monitor) func(context.Context, string) ([]netip.Addr, error) {
	if logf == nil {
		logf = logger.Discard
	}
	bootstrap := lookupFunc(MakeLookupFunc(logf, netMon))
	physical := func(ctx context.Context, host string) ([]netip.Addr, error) {
		if netMon == nil {
			return nil, errors.New("physical DNS requires a network monitor")
		}
		// Use the netns dialer directly so Apple platforms bind each DNS
		// socket to the physical default-route interface. Keeping the actual
		// *net.UDPConn type visible also lets net.Resolver use DNS datagrams.
		dialer := netns.NewDialer(logf, netMon)
		return lookupPhysicalDNS(ctx, host, logf, dialer.DialContext)
	}
	return makeLookupFuncWithPhysicalDNS(logf, bootstrap, physical)
}

func makeLookupFuncWithPhysicalDNS(logf logger.Logf, bootstrap, physical lookupFunc) lookupFunc {
	if logf == nil {
		logf = logger.Discard
	}
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		bootstrapCtx, cancel := context.WithTimeout(ctx, bootstrapStageTimeout)
		ips, bootstrapErr := bootstrap(bootstrapCtx, host)
		cancel()
		ips = filterUsableIPs(ips)
		if len(ips) != 0 {
			return ips, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if bootstrapErr == nil {
			bootstrapErr = errors.New("bootstrap DNS returned no usable IPs")
		}
		logf("dnsfallback: bootstrap DNS failed for %q: %v; trying physical UDP/TCP DNS", host, bootstrapErr)

		ips, physicalErr := physical(ctx, host)
		ips = filterUsableIPs(ips)
		if len(ips) != 0 {
			return ips, nil
		}
		if physicalErr == nil {
			physicalErr = errors.New("physical DNS returned no usable IPs")
		}
		logf("dnsfallback: physical UDP/TCP DNS failed for %q: %v", host, physicalErr)
		return nil, fmt.Errorf("bootstrap DNS failed: %v; physical DNS failed: %w", bootstrapErr, physicalErr)
	}
}

func usableIPs(ips []netip.Addr) bool {
	for _, ip := range ips {
		if ip.IsValid() && !tsaddr.IsSyntheticDNSIP(ip) {
			return true
		}
	}
	return false
}

type physicalDNSQueryFunc func(ctx context.Context, host, server, network string) ([]netip.Addr, error)

func lookupPhysicalDNS(ctx context.Context, host string, logf logger.Logf, dial netx.DialFunc) ([]netip.Addr, error) {
	query := func(ctx context.Context, host, server, network string) ([]netip.Addr, error) {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, requestedNetwork, _ string) (net.Conn, error) {
				dialNetwork := requestedNetwork
				if network == "tcp" {
					// Force stream DNS for the explicit TCP retry. net.Resolver
					// determines DNS framing from the returned connection type.
					dialNetwork = "tcp"
				}
				return dial(ctx, dialNetwork, server)
			},
		}
		return resolver.LookupNetIP(ctx, "ip", host)
	}
	return lookupPhysicalDNSWithQuery(ctx, host, logf, physicalDNSServers, query)
}

func lookupPhysicalDNSWithQuery(ctx context.Context, host string, logf logger.Logf, servers []string, query physicalDNSQueryFunc) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, physicalDNSStageTimeout)
	defer cancel()

	type result struct {
		ips     []netip.Addr
		server  string
		network string
		err     error
	}
	results := make(chan result, len(servers))
	for _, server := range servers {
		go func() {
			udpCtx, udpCancel := context.WithTimeout(ctx, physicalDNSUDPTimeout)
			ips, udpErr := query(udpCtx, host, server, "udp")
			udpCancel()
			if usableIPs(ips) {
				results <- result{ips: ips, server: server, network: "udp"}
				return
			}

			if err := ctx.Err(); err != nil {
				results <- result{server: server, network: "udp", err: errors.Join(udpErr, err)}
				return
			}
			tcpCtx, tcpCancel := context.WithTimeout(ctx, physicalDNSTCPTimeout)
			ips, tcpErr := query(tcpCtx, host, server, "tcp")
			tcpCancel()
			if usableIPs(ips) {
				results <- result{ips: ips, server: server, network: "tcp"}
				return
			}
			results <- result{
				server:  server,
				network: "tcp",
				err:     errors.Join(udpErr, tcpErr),
			}
		}()
	}

	var errs []error
	for range servers {
		select {
		case res := <-results:
			if usableIPs(res.ips) {
				ips := filterUsableIPs(res.ips)
				logf("dnsfallback: physical DNS over %s via %s resolved %q to %v", res.network, res.server, host, ips)
				return ips, nil
			}
			if res.err != nil {
				errs = append(errs, fmt.Errorf("%s via %s: %w", res.network, res.server, res.err))
			}
		case <-ctx.Done():
			return nil, errors.Join(append(errs, ctx.Err())...)
		}
	}
	return nil, errors.Join(errs...)
}

func filterUsableIPs(ips []netip.Addr) []netip.Addr {
	filtered := ips[:0]
	for _, ip := range ips {
		ip = ip.Unmap()
		if ip.IsValid() && !tsaddr.IsSyntheticDNSIP(ip) {
			filtered = append(filtered, ip)
		}
	}
	return filtered
}

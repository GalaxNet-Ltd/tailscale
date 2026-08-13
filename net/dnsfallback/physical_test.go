// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dnsfallback

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

func TestPhysicalDNSServersAreLiteral(t *testing.T) {
	for _, server := range physicalDNSServers {
		if _, err := netip.ParseAddrPort(server); err != nil {
			t.Errorf("physical DNS server %q is not a literal IP:port: %v", server, err)
		}
	}
}

func TestLookupWithPhysicalDNSFallback(t *testing.T) {
	real := netip.MustParseAddr("203.0.113.10")
	synthetic := netip.MustParseAddr("198.18.1.2")

	t.Run("bootstrap-has-priority", func(t *testing.T) {
		physicalCalls := 0
		lookup := makeLookupFuncWithPhysicalDNS(t.Logf,
			func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{real}, nil
			},
			func(context.Context, string) ([]netip.Addr, error) {
				physicalCalls++
				return nil, errors.New("unexpected physical lookup")
			})
		ips, err := lookup(context.Background(), "control.example")
		if err != nil || !usableIPs(ips) {
			t.Fatalf("lookup = %v, %v; want bootstrap result", ips, err)
		}
		if physicalCalls != 0 {
			t.Fatalf("physical lookup called %d times; want 0", physicalCalls)
		}
	})

	t.Run("bootstrap-result-filters-synthetic-addresses", func(t *testing.T) {
		lookup := makeLookupFuncWithPhysicalDNS(t.Logf,
			func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{synthetic, real}, nil
			},
			func(context.Context, string) ([]netip.Addr, error) {
				return nil, errors.New("unexpected physical lookup")
			})
		ips, err := lookup(context.Background(), "control.example")
		if err != nil || len(ips) != 1 || ips[0] != real {
			t.Fatalf("lookup = %v, %v; want only %v", ips, err, real)
		}
	})

	t.Run("bootstrap-failure-uses-physical-and-logs", func(t *testing.T) {
		var logs strings.Builder
		lookup := makeLookupFuncWithPhysicalDNS(
			func(format string, args ...any) { fmt.Fprintf(&logs, format, args...) },
			func(context.Context, string) ([]netip.Addr, error) {
				return nil, errors.New("bootstrap unavailable")
			},
			func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{real}, nil
			})
		ips, err := lookup(context.Background(), "control.example")
		if err != nil || !usableIPs(ips) {
			t.Fatalf("lookup = %v, %v; want physical result", ips, err)
		}
		if got := logs.String(); !strings.Contains(got, "trying physical UDP/TCP DNS") {
			t.Fatalf("missing physical fallback log in %q", got)
		}
	})

	t.Run("synthetic-bootstrap-answer-uses-physical", func(t *testing.T) {
		lookup := makeLookupFuncWithPhysicalDNS(t.Logf,
			func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{synthetic}, nil
			},
			func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{real}, nil
			})
		ips, err := lookup(context.Background(), "control.example")
		if err != nil || !usableIPs(ips) || ips[0] != real {
			t.Fatalf("lookup = %v, %v; want %v", ips, err, real)
		}
	})

	t.Run("physical-failure-is-logged", func(t *testing.T) {
		var logs strings.Builder
		lookup := makeLookupFuncWithPhysicalDNS(
			func(format string, args ...any) { fmt.Fprintf(&logs, format, args...) },
			func(context.Context, string) ([]netip.Addr, error) {
				return nil, errors.New("bootstrap unavailable")
			},
			func(context.Context, string) ([]netip.Addr, error) {
				return nil, errors.New("physical unavailable")
			})
		_, err := lookup(context.Background(), "control.example")
		if err == nil {
			t.Fatal("lookup unexpectedly succeeded")
		}
		if got := logs.String(); !strings.Contains(got, `physical UDP/TCP DNS failed for "control.example"`) {
			t.Fatalf("missing always-on failure log in %q", got)
		}
	})
}

func TestPhysicalDNSRetriesTCP(t *testing.T) {
	real := netip.MustParseAddr("203.0.113.10")
	var mu sync.Mutex
	var networks []string
	query := func(_ context.Context, _, _, network string) ([]netip.Addr, error) {
		mu.Lock()
		networks = append(networks, network)
		mu.Unlock()
		if network == "udp" {
			return nil, errors.New("UDP blocked")
		}
		return []netip.Addr{real}, nil
	}
	var logs strings.Builder
	ips, err := lookupPhysicalDNSWithQuery(
		context.Background(),
		"control.example",
		func(format string, args ...any) { fmt.Fprintf(&logs, format, args...) },
		[]string{"192.0.2.53:53"},
		query,
	)
	if err != nil || len(ips) != 1 || ips[0] != real {
		t.Fatalf("lookup = %v, %v; want %v", ips, err, real)
	}
	mu.Lock()
	gotNetworks := append([]string(nil), networks...)
	mu.Unlock()
	if fmt.Sprint(gotNetworks) != "[udp tcp]" {
		t.Fatalf("networks = %v; want [udp tcp]", gotNetworks)
	}
	if got := logs.String(); !strings.Contains(got, "physical DNS over tcp") {
		t.Fatalf("missing TCP success log in %q", got)
	}
}

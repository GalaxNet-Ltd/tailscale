// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package tsdial

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gaissmai/bart"
	"tailscale.com/net/netmon"
)

func TestNewControlPlaneDNSResolver(t *testing.T) {
	d := NewDialer(netmon.NewStatic())
	var logs strings.Builder
	r := d.NewControlPlaneDNSResolver(func(format string, args ...any) {
		fmt.Fprintf(&logs, format, args...)
	})
	if r.LookupIPFallback == nil {
		t.Fatal("LookupIPFallback is nil")
	}
	if !r.UseLastGood {
		t.Fatal("UseLastGood is false")
	}
	if r.ForwardTimeout != 2*time.Second {
		t.Fatalf("ForwardTimeout = %v; want 2s", r.ForwardTimeout)
	}
	if r.RejectIP == nil || !r.RejectIP(netip.MustParseAddr("198.18.1.2")) {
		t.Fatal("resolver does not reject synthetic DNS IP")
	}
	if r.RejectIP(netip.MustParseAddr("203.0.113.10")) {
		t.Fatal("resolver rejects non-synthetic IP")
	}
	if got := logs.String(); !strings.Contains(got, "control-plane DNS safeguard enabled") {
		t.Fatalf("missing always-on safeguard log in %q", got)
	}
}

func TestUserDialPlan(t *testing.T) {
	tests := []struct {
		name           string
		addr           string
		routes         map[netip.Prefix]bool // nil means no routes configured
		useNetstackFor func(netip.Addr) bool // nil means not set
		wantVia        bool
		wantAddr       netip.AddrPort
	}{
		{
			name:     "loopback_no_routes",
			addr:     "127.0.0.1:8080",
			wantVia:  false,
			wantAddr: netip.MustParseAddrPort("127.0.0.1:8080"),
		},
		{
			name:     "loopback_v6_no_routes",
			addr:     "[::1]:8080",
			wantVia:  false,
			wantAddr: netip.MustParseAddrPort("[::1]:8080"),
		},
		{
			name: "tailscale_ip_in_routes",
			addr: "100.64.1.1:22",
			routes: map[netip.Prefix]bool{
				netip.MustParsePrefix("100.64.0.0/10"): true,
			},
			wantVia:  true,
			wantAddr: netip.MustParseAddrPort("100.64.1.1:22"),
		},
		{
			name: "non_tailscale_ip_in_local_routes",
			addr: "10.0.0.5:80",
			routes: map[netip.Prefix]bool{
				netip.MustParsePrefix("100.64.0.0/10"): true,
				netip.MustParsePrefix("10.0.0.0/8"):    false, // local route
			},
			wantVia:  false,
			wantAddr: netip.MustParseAddrPort("10.0.0.5:80"),
		},
		{
			name: "loopback_with_routes_configured",
			addr: "127.0.0.1:3000",
			routes: map[netip.Prefix]bool{
				netip.MustParsePrefix("100.64.0.0/10"): true,
			},
			wantVia:  false,
			wantAddr: netip.MustParseAddrPort("127.0.0.1:3000"),
		},
		{
			name: "netstack_for_ip",
			addr: "100.100.100.100:53",
			useNetstackFor: func(ip netip.Addr) bool {
				return ip == netip.MustParseAddr("100.100.100.100")
			},
			wantVia:  true,
			wantAddr: netip.MustParseAddrPort("100.100.100.100:53"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Dialer{}
			if tt.routes != nil {
				rt := &bart.Table[bool]{}
				for pfx, v := range tt.routes {
					rt.Insert(pfx, v)
				}
				d.routes.Store(rt)
			}
			d.UseNetstackForIP = tt.useNetstackFor

			ipp, viaTailscale, err := d.UserDialPlan(context.Background(), "tcp", tt.addr)
			if err != nil {
				t.Fatalf("UserDialPlan: %v", err)
			}
			if viaTailscale != tt.wantVia {
				t.Errorf("viaTailscale = %v, want %v", viaTailscale, tt.wantVia)
			}
			if ipp != tt.wantAddr {
				t.Errorf("addr = %v, want %v", ipp, tt.wantAddr)
			}
		})
	}
}

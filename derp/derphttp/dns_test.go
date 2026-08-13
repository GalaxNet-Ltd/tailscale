// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package derphttp

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"tailscale.com/net/dnscache"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
)

func TestNodeDialTargetsUsesDNSCache(t *testing.T) {
	synthetic := netip.MustParseAddr("198.18.1.2")
	v4 := netip.MustParseAddr("203.0.113.10")
	v6 := netip.MustParseAddr("2001:db8::10")
	fallbackCalls := 0
	c := &Client{DNSCache: &dnscache.Resolver{
		Logf:     t.Logf,
		RejectIP: tsaddr.IsSyntheticDNSIP,
		LookupIPForTest: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{synthetic}, nil
		},
		LookupIPFallback: func(context.Context, string) ([]netip.Addr, error) {
			fallbackCalls++
			return []netip.Addr{v6, v4}, nil
		},
	}}

	got, err := c.nodeDialTargets(context.Background(), &tailcfg.DERPNode{HostName: "derp.example"})
	if err != nil {
		t.Fatal(err)
	}
	want := []nodeDialTarget{
		{addr: v4.String(), network: "tcp4"},
		{addr: v6.String(), network: "tcp6"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("nodeDialTargets = %#v; want %#v", got, want)
	}
	if fallbackCalls != 1 {
		t.Fatalf("fallback calls = %d; want 1", fallbackCalls)
	}
}

func TestNodeDialTargetsPreservesExplicitAddress(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.10")
	c := &Client{DNSCache: &dnscache.Resolver{
		Logf: t.Logf,
		LookupIPForTest: func(context.Context, string) ([]netip.Addr, error) {
			return nil, errors.New("DNS unavailable")
		},
	}}
	n := &tailcfg.DERPNode{HostName: "derp.example", IPv4: v4.String()}

	got, err := c.nodeDialTargets(context.Background(), n)
	if err != nil {
		t.Fatal(err)
	}
	want := []nodeDialTarget{{addr: v4.String(), network: "tcp4"}}
	if !slices.Equal(got, want) {
		t.Fatalf("nodeDialTargets = %#v; want %#v", got, want)
	}
}

func TestNodeDialTargetsWithoutDNSCache(t *testing.T) {
	const host = "derp.example"
	got, err := new(Client).nodeDialTargets(context.Background(), &tailcfg.DERPNode{HostName: host})
	if err != nil {
		t.Fatal(err)
	}
	want := []nodeDialTarget{
		{addr: host, network: "tcp4"},
		{addr: host, network: "tcp6"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("nodeDialTargets = %#v; want %#v", got, want)
	}
}

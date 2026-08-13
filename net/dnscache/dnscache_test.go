// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package dnscache

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstest"
)

var dialTest = flag.String("dial-test", "", "if non-empty, addr:port to test dial")

func TestDialer(t *testing.T) {
	if *dialTest == "" {
		t.Skip("skipping; --dial-test is blank")
	}
	r := &Resolver{Logf: t.Logf}
	var std net.Dialer
	dialer := Dialer(std.DialContext, r)
	t0 := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := dialer(ctx, "tcp", *dialTest)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("dialed in %v", time.Since(t0))
	c.Close()
}

func TestDialCall_DNSWasTrustworthy(t *testing.T) {
	type step struct {
		ip  netip.Addr // IP we pretended to dial
		err error      // the dial error or nil for success
	}
	mustIP := netip.MustParseAddr
	errFail := errors.New("some connect failure")
	tests := []struct {
		name  string
		steps []step
		want  bool
	}{
		{
			name: "no-info",
			want: false,
		},
		{
			name: "previous-dial",
			steps: []step{
				{mustIP("2003::1"), nil},
				{mustIP("2003::1"), errFail},
			},
			want: true,
		},
		{
			name: "no-previous-dial",
			steps: []step{
				{mustIP("2003::1"), errFail},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &dialer{
				pastConnect: map[netip.Addr]time.Time{},
			}
			dc := &dialCall{
				d: d,
			}
			for _, st := range tt.steps {
				dc.noteDialResult(st.ip, st.err)
			}
			got := dc.dnsWasTrustworthy()
			if got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}

func TestDialCall_uniqueIPs(t *testing.T) {
	dc := &dialCall{}
	mustIP := netip.MustParseAddr
	errFail := errors.New("some connect failure")
	dc.noteDialResult(mustIP("2003::1"), errFail)
	dc.noteDialResult(mustIP("2003::2"), errFail)
	got := dc.uniqueIPs([]netip.Addr{
		mustIP("2003::1"),
		mustIP("2003::2"),
		mustIP("2003::2"),
		mustIP("2003::3"),
		mustIP("2003::3"),
		mustIP("2003::4"),
		mustIP("2003::4"),
	})
	want := []netip.Addr{
		mustIP("2003::3"),
		mustIP("2003::4"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v; want %v", got, want)
	}
}

func TestResolverAllHostStaticResult(t *testing.T) {
	r := &Resolver{
		Logf:       t.Logf,
		SingleHost: "foo.bar",
		SingleHostStaticResult: []netip.Addr{
			netip.MustParseAddr("2001:4860:4860::8888"),
			netip.MustParseAddr("2001:4860:4860::8844"),
			netip.MustParseAddr("8.8.8.8"),
			netip.MustParseAddr("8.8.4.4"),
		},
	}
	ip4, ip6, allIPs, err := r.LookupIP(context.Background(), "foo.bar")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ip4.String(), "8.8.8.8"; got != want {
		t.Errorf("ip4 got %q; want %q", got, want)
	}
	if got, want := ip6.String(), "2001:4860:4860::8888"; got != want {
		t.Errorf("ip4 got %q; want %q", got, want)
	}
	if got, want := fmt.Sprintf("%q", allIPs), `["2001:4860:4860::8888" "2001:4860:4860::8844" "8.8.8.8" "8.8.4.4"]`; got != want {
		t.Errorf("allIPs got %q; want %q", got, want)
	}

	_, _, _, err = r.LookupIP(context.Background(), "bad")
	if got, want := fmt.Sprint(err), `dnscache: unexpected hostname "bad" doesn't match expected "foo.bar"`; got != want {
		t.Errorf("bad dial error got %q; want %q", got, want)
	}
}

func TestShouldTryBootstrap(t *testing.T) {
	tstest.Replace(t, &debug, func() bool { return true })

	type step struct {
		ip  netip.Addr // IP we pretended to dial
		err error      // the dial error or nil for success
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	deadlineExceeded, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	ctx := context.Background()
	errFailed := errors.New("some failure")

	cacheWithFallback := &Resolver{
		Logf: t.Logf,
		LookupIPFallback: func(_ context.Context, _ string) ([]netip.Addr, error) {
			panic("unimplemented")
		},
	}
	cacheNoFallback := &Resolver{Logf: t.Logf}

	testCases := []struct {
		name       string
		steps      []step
		ctx        context.Context
		err        error
		noFallback bool
		want       bool
	}{
		{
			name: "no-error",
			ctx:  ctx,
			err:  nil,
			want: false,
		},
		{
			name: "canceled",
			ctx:  canceled,
			err:  errFailed,
			want: false,
		},
		{
			name: "deadline-exceeded",
			ctx:  deadlineExceeded,
			err:  errFailed,
			want: false,
		},
		{
			name:       "no-fallback",
			ctx:        ctx,
			err:        errFailed,
			noFallback: true,
			want:       false,
		},
		{
			name: "dns-was-trustworthy",
			ctx:  ctx,
			err:  errFailed,
			steps: []step{
				{netip.MustParseAddr("2003::1"), nil},
				{netip.MustParseAddr("2003::1"), errFailed},
			},
			want: false,
		},
		{
			name: "should-bootstrap",
			ctx:  ctx,
			err:  errFailed,
			want: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			d := &dialer{
				pastConnect: map[netip.Addr]time.Time{},
			}
			if tt.noFallback {
				d.dnsCache = cacheNoFallback
			} else {
				d.dnsCache = cacheWithFallback
			}
			dc := &dialCall{d: d}
			for _, st := range tt.steps {
				dc.noteDialResult(st.ip, st.err)
			}
			got := d.shouldTryBootstrap(tt.ctx, tt.err, dc)
			if got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
		})
	}
}

func TestSingleHostStaticResult(t *testing.T) {
	v4 := netip.MustParseAddr("0.0.0.1")
	v6 := netip.MustParseAddr("2001::a")

	tests := []struct {
		name    string
		static  []netip.Addr
		wantIP  netip.Addr
		wantIP6 netip.Addr
		wantAll []netip.Addr
	}{
		{
			name:    "just-v6",
			static:  []netip.Addr{v6},
			wantIP:  v6,
			wantIP6: v6,
			wantAll: []netip.Addr{v6},
		},
		{
			name:    "just-v4",
			static:  []netip.Addr{v4},
			wantIP:  v4,
			wantIP6: netip.Addr{},
			wantAll: []netip.Addr{v4},
		},
		{
			name:    "v6-then-v4",
			static:  []netip.Addr{v6, v4},
			wantIP:  v4,
			wantIP6: v6,
			wantAll: []netip.Addr{v6, v4},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Resolver{
				SingleHost:             "example.com",
				SingleHostStaticResult: tt.static,
			}
			ip, ip6, all, err := r.LookupIP(context.Background(), "example.com")
			if err != nil {
				t.Fatal(err)
			}
			if ip != tt.wantIP {
				t.Errorf("got ip %v; want %v", ip, tt.wantIP)
			}
			if ip6 != tt.wantIP6 {
				t.Errorf("got ip6 %v; want %v", ip6, tt.wantIP6)
			}
			if !slices.Equal(all, tt.wantAll) {
				t.Errorf("got all %v; want %v", all, tt.wantAll)
			}
		})
	}
}

func TestResolverRejectIP(t *testing.T) {
	synthetic := netip.MustParseAddr("198.18.1.2")
	mappedSynthetic := netip.MustParseAddr("::ffff:198.18.1.2")
	real := netip.MustParseAddr("203.0.113.10")
	rejectSynthetic := func(ip netip.Addr) bool {
		return ip == synthetic
	}

	t.Run("synthetic-uses-fallback-and-logs", func(t *testing.T) {
		var logs strings.Builder
		forwardCalls, fallbackCalls := 0, 0
		r := &Resolver{
			Logf: func(format string, args ...any) {
				fmt.Fprintf(&logs, format, args...)
			},
			RejectIP: rejectSynthetic,
			LookupIPForTest: func(context.Context, string) ([]netip.Addr, error) {
				forwardCalls++
				return []netip.Addr{mappedSynthetic}, nil
			},
			LookupIPFallback: func(context.Context, string) ([]netip.Addr, error) {
				fallbackCalls++
				return []netip.Addr{real}, nil
			},
		}

		ip, _, all, err := r.LookupIP(context.Background(), "control.example")
		if err != nil {
			t.Fatal(err)
		}
		if ip != real || !slices.Equal(all, []netip.Addr{real}) {
			t.Fatalf("LookupIP = %v, %v; want %v", ip, all, real)
		}
		if forwardCalls != 1 || fallbackCalls != 1 {
			t.Fatalf("calls: forward=%d fallback=%d; want 1, 1", forwardCalls, fallbackCalls)
		}
		if got := logs.String(); !strings.Contains(got, `dnscache: rejected forward DNS answer for "control.example" containing synthetic IPs [198.18.1.2]`) {
			t.Fatalf("missing always-on rejection log in %q", got)
		}

		// The accepted fallback result, rather than the synthetic forward
		// result, is cached.
		ip, _, _, err = r.LookupIP(context.Background(), "control.example")
		if err != nil || ip != real {
			t.Fatalf("cached LookupIP = %v, %v; want %v, nil", ip, err, real)
		}
		if forwardCalls != 1 || fallbackCalls != 1 {
			t.Fatalf("cached lookup called resolvers: forward=%d fallback=%d", forwardCalls, fallbackCalls)
		}
	})

	t.Run("mixed-answer-keeps-real-address", func(t *testing.T) {
		fallbackCalls := 0
		r := &Resolver{
			Logf:     t.Logf,
			RejectIP: rejectSynthetic,
			LookupIPForTest: func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{synthetic, real}, nil
			},
			LookupIPFallback: func(context.Context, string) ([]netip.Addr, error) {
				fallbackCalls++
				return nil, errors.New("unexpected fallback")
			},
		}
		ip, _, all, err := r.LookupIP(context.Background(), "mixed.example")
		if err != nil {
			t.Fatal(err)
		}
		if ip != real || !slices.Equal(all, []netip.Addr{real}) {
			t.Fatalf("LookupIP = %v, %v; want only %v", ip, all, real)
		}
		if fallbackCalls != 0 {
			t.Fatalf("fallback called %d times; want 0", fallbackCalls)
		}
	})

	t.Run("fallback-answer-is-filtered", func(t *testing.T) {
		r := &Resolver{
			Logf:     t.Logf,
			RejectIP: rejectSynthetic,
			LookupIPForTest: func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{synthetic}, nil
			},
			LookupIPFallback: func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{mappedSynthetic}, nil
			},
		}
		_, _, _, err := r.LookupIP(context.Background(), "bad-fallback.example")
		if err == nil || !strings.Contains(err.Error(), "fallback returned no usable IPs") {
			t.Fatalf("LookupIP error = %v; want no usable fallback IPs", err)
		}
	})
}

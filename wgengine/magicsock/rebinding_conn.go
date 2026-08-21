// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/ipv6"
	"tailscale.com/net/batching"
	"tailscale.com/net/netaddr"
	"tailscale.com/net/packet"
	"tailscale.com/syncs"
	"tailscale.com/types/nettype"
)

// RebindingUDPConn is a UDP socket that can be re-bound.
// Unix has no notion of re-binding a socket, so we swap it out for a new one.
type RebindingUDPConn struct {
	// pconnAtomic is a pointer to the value stored in pconn, but doesn't
	// require acquiring mu. It's used for reads/writes and only upon failure
	// do the reads/writes then check pconn (after acquiring mu) to see if
	// there's been a rebind meanwhile.
	// pconn isn't really needed, but makes some of the code simpler
	// to keep it distinct.
	// Neither is expected to be nil, sockets are bound on creation.
	pconnAtomic atomic.Pointer[nettype.PacketConn]

	mu    syncs.Mutex // held while changing pconn (and pconnAtomic)
	pconn nettype.PacketConn
	port  uint16

	// pconnChanged is closed whenever setConnLocked publishes a replacement
	// socket, and when Close needs to wake recovery waiters. It lets a receive
	// function wait for asynchronous rebind publication without repeatedly
	// reading the same failed socket.
	pconnChanged chan struct{}
}

// setConnLocked sets the provided nettype.PacketConn. It should be called only
// after acquiring RebindingUDPConn.mu. It upgrades the provided
// nettype.PacketConn to a batchingConn when appropriate. This upgrade is
// intentionally pushed closest to where read/write ops occur in order to avoid
// disrupting surrounding code that assumes nettype.PacketConn is a
// *net.UDPConn.
func (c *RebindingUDPConn) setConnLocked(p nettype.PacketConn, network string, batchSize int) {
	upc := batching.TryUpgradeToConn(p, network, batchSize, "magicsock_udp_rxq_overflows")
	c.pconn = upc
	c.pconnAtomic.Store(&upc)
	c.port = uint16(c.localAddrLocked().Port)
	c.notifyPConnChangedLocked()
}

// notifyPConnChangedLocked wakes waiters and prepares the notification used by
// the next socket generation. c.mu must be held.
func (c *RebindingUDPConn) notifyPConnChangedLocked() {
	if c.pconnChanged != nil {
		close(c.pconnChanged)
	}
	c.pconnChanged = make(chan struct{})
}

// currentConn returns c's current pconn, acquiring c.mu in the process.
func (c *RebindingUDPConn) currentConn() nettype.PacketConn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pconn
}

// loadConn returns c's current pconn without locking. It is used to snapshot
// the socket on the receive hot path; recovery validates changes under c.mu.
func (c *RebindingUDPConn) loadConn() nettype.PacketConn {
	return *c.pconnAtomic.Load()
}

// waitForConnChange waits until previous is no longer the active socket, Close
// wakes the waiter, or maxWait expires. The timeout is a bounded fallback for a
// failed or throttled rebind; successful socket publication wakes immediately.
func (c *RebindingUDPConn) waitForConnChange(previous nettype.PacketConn, maxWait time.Duration) {
	c.mu.Lock()
	if c.pconn != previous {
		c.mu.Unlock()
		return
	}
	if c.pconnChanged == nil {
		c.pconnChanged = make(chan struct{})
	}
	changed := c.pconnChanged
	c.mu.Unlock()

	timer := time.NewTimer(maxWait)
	defer timer.Stop()
	select {
	case <-changed:
	case <-timer.C:
	}
}

func (c *RebindingUDPConn) readFromWithInitPconn(pconn nettype.PacketConn, b []byte) (int, netip.AddrPort, error) {
	for {
		n, addr, err := pconn.ReadFromUDPAddrPort(b)
		if err != nil && pconn != c.currentConn() {
			pconn = *c.pconnAtomic.Load()
			continue
		}
		return n, addr, err
	}
}

// ReadFromUDPAddrPort reads a packet from c into b.
// It returns the number of bytes copied and the source address.
func (c *RebindingUDPConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	return c.readFromWithInitPconn(c.loadConn(), b)
}

// WriteWireGuardBatchTo writes buffs to addr. It serves primarily as an alias
// for [batching.Conn.WriteBatchTo], with fallback to single packet operations
// if c.pconn is not a [batching.Conn].
//
// WriteWireGuardBatchTo assumes buffs are WireGuard packets, which is notable
// for Geneve encapsulation: Geneve protocol is set to [packet.GeneveProtocolWireGuard],
// and the control bit is left unset.
func (c *RebindingUDPConn) WriteWireGuardBatchTo(buffs [][]byte, addr epAddr, offset int) error {
	if offset != packet.GeneveFixedHeaderLength {
		return fmt.Errorf("RebindingUDPConn.WriteWireGuardBatchTo: [unexpected] offset (%d) != Geneve header length (%d)", offset, packet.GeneveFixedHeaderLength)
	}
	gh := packet.GeneveHeader{
		Protocol: packet.GeneveProtocolWireGuard,
		VNI:      addr.vni,
	}
	for {
		pconn := *c.pconnAtomic.Load()
		b, ok := pconn.(batching.Conn)
		if !ok {
			for _, buf := range buffs {
				if gh.VNI.IsSet() {
					gh.Encode(buf)
				} else {
					buf = buf[offset:]
				}
				_, err := c.writeToUDPAddrPortWithInitPconn(pconn, buf, addr.ap)
				if err != nil {
					return err
				}
			}
			return nil
		}
		err := b.WriteBatchTo(buffs, addr.ap, gh, offset)
		if err != nil {
			if pconn != c.currentConn() {
				continue
			}
			return err
		}
		return err
	}
}

// ReadBatch is an alias for [batching.Conn.ReadBatch] with fallback to single
// packet operations if c.pconn is not a [batching.Conn].
func (c *RebindingUDPConn) ReadBatch(msgs []ipv6.Message, flags int) (int, error) {
	for {
		pconn := *c.pconnAtomic.Load()
		b, ok := pconn.(batching.Conn)
		if !ok {
			n, ap, err := c.readFromWithInitPconn(pconn, msgs[0].Buffers[0])
			if err == nil {
				msgs[0].N = n
				msgs[0].Addr = net.UDPAddrFromAddrPort(netaddr.Unmap(ap))
				return 1, nil
			}
			return 0, err
		}
		n, err := b.ReadBatch(msgs, flags)
		if err != nil && pconn != c.currentConn() {
			continue
		}
		return n, err
	}
}

func (c *RebindingUDPConn) Port() uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.port
}

func (c *RebindingUDPConn) LocalAddr() *net.UDPAddr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.localAddrLocked()
}

func (c *RebindingUDPConn) localAddrLocked() *net.UDPAddr {
	return c.pconn.LocalAddr().(*net.UDPAddr)
}

// errNilPConn is returned by RebindingUDPConn.Close when there is no current pconn.
// It is for internal use only and should not be returned to users.
var errNilPConn = errors.New("nil pconn")

func (c *RebindingUDPConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.closeLocked()
	c.notifyPConnChangedLocked()
	return err
}

func (c *RebindingUDPConn) closeLocked() error {
	if c.pconn == nil {
		return errNilPConn
	}
	c.port = 0
	return c.pconn.Close()
}

func (c *RebindingUDPConn) writeToUDPAddrPortWithInitPconn(pconn nettype.PacketConn, b []byte, addr netip.AddrPort) (int, error) {
	for {
		n, err := pconn.WriteToUDPAddrPort(b, addr)
		if err != nil && pconn != c.currentConn() {
			pconn = *c.pconnAtomic.Load()
			continue
		}
		return n, err
	}
}

func (c *RebindingUDPConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	return c.writeToUDPAddrPortWithInitPconn(*c.pconnAtomic.Load(), b, addr)
}

func (c *RebindingUDPConn) SyscallConn() (syscall.RawConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sc, ok := c.pconn.(syscall.Conn)
	if !ok {
		return nil, errUnsupportedConnType
	}
	return sc.SyscallConn()
}

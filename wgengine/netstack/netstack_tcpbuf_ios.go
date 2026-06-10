// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ios

package netstack

import (
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

const (
	// tcp{RX,TX}Buf{Min,Def,Max}Size mirror gVisor defaults. We leave these
	// unchanged on iOS for now as to not increase pressure towards the
	// NetworkExtension memory limit.
	// TODO(jwhited): test memory/throughput impact of collapsing to values in _default.go
	tcpRXBufMinSize = tcp.MinBufferSize
	tcpRXBufDefSize = tcp.DefaultSendBufferSize
	// NOVA_MOD: use default value becase Nova is not in NE
	// tcpRXBufMaxSize = tcp.MaxBufferSize
	tcpRXBufMaxSize = 8 << 20 // 8MiB

	tcpTXBufMinSize = tcp.MinBufferSize
	tcpTXBufDefSize = tcp.DefaultReceiveBufferSize
	// NOVA_MOD: use default value becase Nova is not in NE
	// tcpTXBufMaxSize = tcp.MaxBufferSize
	tcpTXBufMaxSize = 6 << 20 // 6MiB
)

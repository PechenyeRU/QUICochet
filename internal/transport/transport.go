package transport

import (
	"net"
	"syscall"
)

// Verify rawFdConn satisfies syscall.RawConn at compile time.
var _ syscall.RawConn = (*rawFdConn)(nil)

// Transport is the interface for sending and receiving spoofed packets
type Transport interface {
	// Send sends a packet with spoofed source IP
	Send(payload []byte, dstIP net.IP, dstPort uint16) error

	// Receive receives a packet into buf, returns bytes written, source IP and port
	Receive(buf []byte) (n int, srcIP net.IP, srcPort uint16, err error)

	// Close closes the transport
	Close() error

	// LocalPort returns the local port being used
	LocalPort() uint16

	// SetReadBuffer sets the read buffer size
	SetReadBuffer(size int) error

	// SetWriteBuffer sets the write buffer size
	SetWriteBuffer(size int) error
}

// Config holds transport configuration
type Config struct {
	// SourceIP is the IP to use as source when sending packets
	SourceIP net.IP

	// SourceIPv6 is the IPv6 to use as source when sending packets
	SourceIPv6 net.IP

	// ListenPort is the port to listen on for incoming packets
	ListenPort uint16

	// PeerSpoofIP is the expected source IP of incoming packets from peer
	PeerSpoofIP net.IP

	// PeerSpoofIPv6 is the expected source IPv6 of incoming packets from peer
	PeerSpoofIPv6 net.IP

	// BufferSize is the size of pool buffers
	BufferSize int

	// ReadBuffer is the SO_RCVBUF size for the receive socket
	ReadBuffer int

	// WriteBuffer is the SO_SNDBUF size for the send socket
	WriteBuffer int

	// MTU is the maximum transmission unit
	MTU int

	// ProtocolNumber is the custom IP protocol number (1-255)
	// Used for raw transport type
	ProtocolNumber int

	// ICMPEchoID overrides the default ICMP echo ID.
	// Derived from shared secret so both peers use the same value.
	// 0 = use default.
	ICMPEchoID uint16
}

// rawFdConn implements syscall.RawConn for raw socket file descriptors.
// quic-go only uses Control() to set socket options (SO_RCVBUF/SO_SNDBUF);
// Read/Write are no-ops since we handle I/O via syscall directly.
type rawFdConn struct{ fd int }

func (c *rawFdConn) Control(f func(uintptr)) error { f(uintptr(c.fd)); return nil }
func (c *rawFdConn) Read(func(uintptr) bool) error { return nil }
func (c *rawFdConn) Write(func(uintptr) bool) error { return nil }

// Validate validates the transport config
func (c *Config) Validate() error {
	if c.SourceIP == nil && c.SourceIPv6 == nil {
		return ErrNoSourceIP
	}
	if c.BufferSize == 0 {
		c.BufferSize = 65535
	}
	if c.MTU == 0 {
		c.MTU = 1400
	}
	return nil
}

func (c *Config) icmpEchoID() uint16 {
	if c.ICMPEchoID == 0 {
		panic("ICMPEchoID must be set before creating ICMP transport")
	}
	return c.ICMPEchoID
}

// IsIPv6 returns true if using IPv6
func (c *Config) IsIPv6() bool {
	return c.SourceIP == nil || c.SourceIP.To4() == nil
}

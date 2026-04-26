package transport

import (
	"net"
	"strings"
	"testing"
)

// TestNewRawTransportDualStackAsymmetricPeerSpoofRejected pins the
// M-3 hardening: in dual-stack, configuring peer-spoof for one
// family but not the other leaves an unfiltered recv path on the
// other side. Refuse rather than silently load the half-baked config.
func TestNewRawTransportDualStackAsymmetricPeerSpoofRejected(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
	}{
		{
			name: "v4 peer-spoof only",
			cfg: &Config{
				SourceIP:       net.ParseIP("10.0.0.1"),
				SourceIPv6:     net.ParseIP("2001:db80::1"),
				PeerSpoofIP:    net.ParseIP("10.0.0.2"),
				ListenPort:     0,
				BufferSize:     65535,
				ProtocolNumber: 200,
			},
		},
		{
			name: "v6 peer-spoof only",
			cfg: &Config{
				SourceIP:       net.ParseIP("10.0.0.1"),
				SourceIPv6:     net.ParseIP("2001:db80::1"),
				PeerSpoofIPv6:  net.ParseIP("2001:db80::2"),
				ListenPort:     0,
				BufferSize:     65535,
				ProtocolNumber: 200,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr, err := NewRawTransport(tc.cfg)
			if err == nil {
				tr.Close()
				t.Fatal("NewRawTransport accepted asymmetric dual-stack peer-spoof — open recv path")
			}
			if !strings.Contains(err.Error(), "symmetric peer-spoof") {
				t.Errorf("error should mention symmetric requirement, got: %v", err)
			}
		})
	}
}

// TestNewICMPTransportDualStackAsymmetricPeerSpoofRejected mirrors
// the udp + raw tests for the ICMP transport. The icmp.go init also
// has the symmetric guard but no dedicated test until now — would
// have missed a copy-paste regression of the udp guard.
func TestNewICMPTransportDualStackAsymmetricPeerSpoofRejected(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
	}{
		{
			name: "v4 peer-spoof only",
			cfg: &Config{
				SourceIP:    net.ParseIP("10.0.0.1"),
				SourceIPv6:  net.ParseIP("2001:db80::1"),
				PeerSpoofIP: net.ParseIP("10.0.0.2"),
				ListenPort:  0,
				BufferSize:  65535,
				ICMPEchoID:  0xbeef,
			},
		},
		{
			name: "v6 peer-spoof only",
			cfg: &Config{
				SourceIP:      net.ParseIP("10.0.0.1"),
				SourceIPv6:    net.ParseIP("2001:db80::1"),
				PeerSpoofIPv6: net.ParseIP("2001:db80::2"),
				ListenPort:    0,
				BufferSize:    65535,
				ICMPEchoID:    0xbeef,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr, err := NewICMPTransport(tc.cfg, ICMPModeReply)
			if err == nil {
				tr.Close()
				t.Fatal("NewICMPTransport accepted asymmetric dual-stack peer-spoof — open recv path")
			}
			if !strings.Contains(err.Error(), "symmetric peer-spoof") {
				t.Errorf("error should mention symmetric requirement, got: %v", err)
			}
		})
	}
}

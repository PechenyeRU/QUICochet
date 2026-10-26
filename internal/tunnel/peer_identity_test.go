package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"testing"

	"github.com/quic-go/quic-go"

	"github.com/pechenyeru/quiccochet/internal/crypto"
)

func derivePeerIdentityCertificate(t *testing.T, seed byte) (*tls.Certificate, *x509.Certificate) {
	t.Helper()
	var secret [crypto.KeySize]byte
	for i := range secret {
		secret[i] = seed + byte(i)
	}
	cert, err := crypto.DeriveTLSCertificate(secret)
	if err != nil {
		t.Fatalf("derive certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert, leaf
}

func TestValidatePeerConnection(t *testing.T) {
	ipA := netip.MustParseAddr("198.51.100.10")
	ipB := netip.MustParseAddr("198.51.100.20")
	certA, leafA := derivePeerIdentityCertificate(t, 1)
	certB, _ := derivePeerIdentityCertificate(t, 101)
	server := &Server{peerCerts: map[netip.Addr]*tls.Certificate{ipA: certA, ipB: certB}}

	tests := []struct {
		name     string
		remote   net.Addr
		leaf     *x509.Certificate
		resumed  bool
		wantFail bool
	}{
		{name: "full handshake matching peer", remote: &net.UDPAddr{IP: net.IP(ipA.AsSlice()), Port: 4444}, leaf: leafA},
		{name: "resumed matching peer", remote: &net.UDPAddr{IP: net.IP(ipA.AsSlice()), Port: 4444}, leaf: leafA, resumed: true},
		{name: "certificate A from peer B IP", remote: &net.UDPAddr{IP: net.IP(ipB.AsSlice()), Port: 5555}, leaf: leafA, wantFail: true},
		{name: "resumed certificate A from peer B IP", remote: &net.UDPAddr{IP: net.IP(ipB.AsSlice()), Port: 5555}, leaf: leafA, resumed: true, wantFail: true},
		{name: "unknown peer IP", remote: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 4444}, leaf: leafA, wantFail: true},
		{name: "missing peer certificate", remote: &net.UDPAddr{IP: net.IP(ipA.AsSlice()), Port: 4444}, wantFail: true},
		{name: "IPv4 mapped peer", remote: &net.UDPAddr{IP: net.ParseIP("::ffff:198.51.100.10"), Port: 4444}, leaf: leafA},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := quic.ConnectionState{TLS: tls.ConnectionState{DidResume: tc.resumed}}
			if tc.leaf != nil {
				state.TLS.PeerCertificates = []*x509.Certificate{tc.leaf}
			}
			err := server.validatePeerConnection(tc.remote, state)
			if tc.wantFail && err == nil {
				t.Fatal("expected peer identity validation to fail")
			}
			if !tc.wantFail && err != nil {
				t.Fatalf("peer identity validation failed: %v", err)
			}
		})
	}
}

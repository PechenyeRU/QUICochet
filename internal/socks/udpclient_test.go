package socks

import (
	"net"
	"sync"
	"testing"
	"time"
)

func newUDPReceiveTestClient(t *testing.T) (*UDPProxyClient, *net.UDPConn, *net.UDPConn) {
	t.Helper()

	listenAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	udpConn, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		t.Fatalf("listen client UDP: %v", err)
	}
	relay, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		udpConn.Close()
		t.Fatalf("listen relay UDP: %v", err)
	}
	stranger, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		udpConn.Close()
		relay.Close()
		t.Fatalf("listen stranger UDP: %v", err)
	}
	t.Cleanup(func() {
		udpConn.Close()
		relay.Close()
		stranger.Close()
	})

	client := &UDPProxyClient{
		udpConn:   udpConn,
		relayAddr: relay.LocalAddr().(*net.UDPAddr),
		bufPool: sync.Pool{New: func() any {
			buf := make([]byte, 65535+22)
			return &buf
		}},
	}
	return client, relay, stranger
}

func socksUDPResponse(payload string) []byte {
	packet := []byte{0, 0, 0, AddrIPv4, 192, 0, 2, 10, 0x01, 0xbb}
	return append(packet, payload...)
}

func sendUDPTestPacket(t *testing.T, sender *net.UDPConn, recipient *net.UDPConn, packet []byte) {
	t.Helper()
	if _, err := sender.WriteToUDP(packet, recipient.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("write UDP packet: %v", err)
	}
}

func assertUDPReceivePayload(t *testing.T, client *UDPProxyClient, want string) {
	t.Helper()
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 64)
	n, srcHost, srcPort, err := client.ReceiveFrom(buf)
	if err != nil {
		t.Fatalf("ReceiveFrom returned an error: %v", err)
	}
	if got := string(buf[:n]); got != want {
		t.Fatalf("payload = %q, want %q", got, want)
	}
	if srcHost != "192.0.2.10" || srcPort != 443 {
		t.Fatalf("source = %s:%d, want 192.0.2.10:443", srcHost, srcPort)
	}
}

func TestUDPProxyClientReceiveFromSenderAndValidation(t *testing.T) {
	t.Run("valid from relay accepted", func(t *testing.T) {
		client, relay, _ := newUDPReceiveTestClient(t)
		sendUDPTestPacket(t, relay, client.udpConn, socksUDPResponse("accepted"))
		assertUDPReceivePayload(t, client, "accepted")
	})

	t.Run("valid from stranger ignored", func(t *testing.T) {
		client, relay, stranger := newUDPReceiveTestClient(t)
		sendUDPTestPacket(t, stranger, client.udpConn, socksUDPResponse("stranger"))
		sendUDPTestPacket(t, relay, client.udpConn, socksUDPResponse("relay"))
		assertUDPReceivePayload(t, client, "relay")
	})

	t.Run("malformed from stranger ignored", func(t *testing.T) {
		client, relay, stranger := newUDPReceiveTestClient(t)
		sendUDPTestPacket(t, stranger, client.udpConn, []byte{0, 0, 0, AddrIPv4, 127})
		sendUDPTestPacket(t, relay, client.udpConn, socksUDPResponse("relay"))
		assertUDPReceivePayload(t, client, "relay")
	})

	t.Run("malformed from relay not fatal", func(t *testing.T) {
		client, relay, _ := newUDPReceiveTestClient(t)
		sendUDPTestPacket(t, relay, client.udpConn, []byte{0, 0, 0, AddrIPv4, 127})
		sendUDPTestPacket(t, relay, client.udpConn, socksUDPResponse("relay"))
		assertUDPReceivePayload(t, client, "relay")
	})

	t.Run("fragmented from relay not fatal", func(t *testing.T) {
		client, relay, _ := newUDPReceiveTestClient(t)
		packet := socksUDPResponse("fragment")
		packet[2] = 1
		sendUDPTestPacket(t, relay, client.udpConn, packet)
		sendUDPTestPacket(t, relay, client.udpConn, socksUDPResponse("relay"))
		assertUDPReceivePayload(t, client, "relay")
	})
}

func TestUDPProxyClientReceiveFromSocketErrorIsFatal(t *testing.T) {
	client, _, _ := newUDPReceiveTestClient(t)
	if err := client.udpConn.Close(); err != nil {
		t.Fatalf("close UDP socket: %v", err)
	}
	if _, _, _, err := client.ReceiveFrom(make([]byte, 64)); err == nil {
		t.Fatal("ReceiveFrom returned nil error for a closed socket")
	}
}

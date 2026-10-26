package tunnel

import (
	"bytes"
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

type udpAssociationTest struct {
	client   *Client
	relay    *net.UDPConn
	original *net.UDPConn
	stranger *net.UDPConn
}

func startUDPAssociationTest(t *testing.T, target string) *udpAssociationTest {
	t.Helper()

	listenAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	relay, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		t.Fatalf("listen relay UDP: %v", err)
	}
	original, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		relay.Close()
		t.Fatalf("listen original client UDP: %v", err)
	}
	stranger, err := net.ListenUDP("udp4", listenAddr)
	if err != nil {
		relay.Close()
		original.Close()
		t.Fatalf("listen stranger client UDP: %v", err)
	}

	if target == "" {
		target = original.LocalAddr().String()
	}
	client := &Client{stopCh: make(chan struct{})}
	controlClient, controlServer := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- client.handleUDP(target, controlServer, relay)
	}()

	t.Cleanup(func() {
		controlClient.Close()
		original.Close()
		stranger.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("handleUDP returned an error during cleanup: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("handleUDP did not stop during cleanup")
		}
	})

	return &udpAssociationTest{client: client, relay: relay, original: original, stranger: stranger}
}

func clientSOCKSUDPDatagram(payload string) []byte {
	packet := []byte{0, 0, 0, 1, 198, 51, 100, 20, 0, 53}
	return append(packet, payload...)
}

func sendClientSOCKSUDPDatagram(t *testing.T, sender *net.UDPConn, relay *net.UDPConn, packet []byte) {
	t.Helper()
	if _, err := sender.WriteToUDP(packet, relay.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("write client UDP datagram: %v", err)
	}
}

func waitUDPAssociation(t *testing.T, client *Client) *udpAssoc {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		var found *udpAssoc
		client.udpAssociations.Range(func(_, value any) bool {
			found = value.(*udpAssoc)
			return false
		})
		if found != nil {
			return found
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("UDP association was not registered")
	return nil
}

func waitUDPClientAddr(t *testing.T, assoc *udpAssoc, want *net.UDPAddr) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if addr := assoc.clientAddr.Load(); addr != nil && addr.IP.Equal(want.IP) && addr.Port == want.Port {
			return
		}
		time.Sleep(time.Millisecond)
	}
	addr := assoc.clientAddr.Load()
	if addr == nil {
		t.Fatalf("client endpoint = nil, want %s", want)
	}
	t.Fatalf("client endpoint = %s, want %s", addr, want)
}

func assertUDPClientAddrStays(t *testing.T, assoc *udpAssoc, want *net.UDPAddr) {
	t.Helper()
	deadline := time.Now().Add(50 * time.Millisecond)
	for time.Now().Before(deadline) {
		addr := assoc.clientAddr.Load()
		if addr == nil || !addr.IP.Equal(want.IP) || addr.Port != want.Port {
			t.Fatalf("client endpoint changed to %v, want %s", addr, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertUDPAssociationReplyGoesToOriginal(t *testing.T, test *udpAssociationTest, assoc *udpAssoc) {
	t.Helper()
	packet := clientSOCKSUDPDatagram("reply")
	if _, err := assoc.conn.WriteToUDP(packet, assoc.clientAddr.Load()); err != nil {
		t.Fatalf("write association reply: %v", err)
	}

	if err := test.original.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set original client deadline: %v", err)
	}
	buf := make([]byte, 64)
	n, _, err := test.original.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read original client reply: %v", err)
	}
	if !bytes.Equal(buf[:n], packet) {
		t.Fatalf("reply = %v, want %v", buf[:n], packet)
	}

	if err := test.stranger.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("set stranger deadline: %v", err)
	}
	if _, _, err := test.stranger.ReadFromUDP(buf); err == nil {
		t.Fatal("stranger received the association reply")
	} else if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read stranger reply: %v", err)
	}
}

func TestHandleUDPPinsDeclaredClientEndpoint(t *testing.T) {
	test := startUDPAssociationTest(t, "")
	assoc := waitUDPAssociation(t, test.client)
	originalAddr := test.original.LocalAddr().(*net.UDPAddr)
	waitUDPClientAddr(t, assoc, originalAddr)

	sendClientSOCKSUDPDatagram(t, test.stranger, test.relay, clientSOCKSUDPDatagram("stranger"))
	assertUDPClientAddrStays(t, assoc, originalAddr)
	sendClientSOCKSUDPDatagram(t, test.original, test.relay, clientSOCKSUDPDatagram("original"))
	waitUDPClientAddr(t, assoc, originalAddr)

	sendClientSOCKSUDPDatagram(t, test.stranger, test.relay, clientSOCKSUDPDatagram("hijack"))
	assertUDPClientAddrStays(t, assoc, originalAddr)
	assertUDPAssociationReplyGoesToOriginal(t, test, assoc)
}

type udpAssociationControlConn struct {
	net.Conn
	remote net.Addr
}

func (c *udpAssociationControlConn) RemoteAddr() net.Addr { return c.remote }

func TestHandleUDPUsesControlIPWithDeclaredPort(t *testing.T) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen relay UDP: %v", err)
	}
	client := &Client{stopCh: make(chan struct{})}
	controlClient, controlServer := net.Pipe()
	defer controlClient.Close()
	wrapped := &udpAssociationControlConn{
		Conn:   controlServer,
		remote: &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 45678},
	}
	done := make(chan error, 1)
	go func() { done <- client.handleUDP("10.0.0.2:12345", wrapped, relay) }()
	defer func() {
		controlServer.Close()
		relay.Close()
		<-done
	}()

	assoc := waitUDPAssociation(t, client)
	waitUDPClientAddr(t, assoc, &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 12345})
}

func TestHandleUDPRejectsWildcardAssociation(t *testing.T) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen relay UDP: %v", err)
	}
	client := &Client{stopCh: make(chan struct{})}
	controlClient, controlServer := net.Pipe()
	defer controlClient.Close()

	if err := client.handleUDP("0.0.0.0:0", controlServer, relay); err == nil {
		t.Fatal("expected wildcard UDP association to be rejected")
	}
	client.udpAssociations.Range(func(_, _ any) bool {
		t.Fatal("wildcard UDP association was registered")
		return false
	})
}

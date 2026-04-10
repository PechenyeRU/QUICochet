package socks

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestParseAddress(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		buf := []byte{0x01, 192, 168, 1, 1, 0x1F, 0x90}
		host, port, n, err := ParseAddress(buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if host != "192.168.1.1" {
			t.Errorf("host = %q, want %q", host, "192.168.1.1")
		}
		if port != 8080 {
			t.Errorf("port = %d, want %d", port, 8080)
		}
		if n != 7 {
			t.Errorf("bytesRead = %d, want %d", n, 7)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		// ::1 with port 443
		buf := make([]byte, 19)
		buf[0] = 0x04
		// IPv6 ::1 = 15 zero bytes then 0x01
		buf[16] = 0x01
		binary.BigEndian.PutUint16(buf[17:19], 443)

		host, port, n, err := ParseAddress(buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if host != "::1" {
			t.Errorf("host = %q, want %q", host, "::1")
		}
		if port != 443 {
			t.Errorf("port = %d, want %d", port, 443)
		}
		if n != 19 {
			t.Errorf("bytesRead = %d, want %d", n, 19)
		}
	})

	t.Run("Domain", func(t *testing.T) {
		buf := []byte{0x03, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x00, 0x50}
		host, port, n, err := ParseAddress(buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if host != "example.com" {
			t.Errorf("host = %q, want %q", host, "example.com")
		}
		if port != 80 {
			t.Errorf("port = %d, want %d", port, 80)
		}
		if n != 15 {
			t.Errorf("bytesRead = %d, want %d", n, 15)
		}
	})

	t.Run("EmptyBuffer", func(t *testing.T) {
		_, _, _, err := ParseAddress([]byte{})
		if err != ErrInvalidAddress {
			t.Errorf("err = %v, want %v", err, ErrInvalidAddress)
		}
	})

	t.Run("SingleByte", func(t *testing.T) {
		_, _, _, err := ParseAddress([]byte{0x01})
		if err != ErrInvalidAddress {
			t.Errorf("err = %v, want %v", err, ErrInvalidAddress)
		}
	})

	t.Run("InvalidAddressType", func(t *testing.T) {
		_, _, _, err := ParseAddress([]byte{0x05, 0x00, 0x00})
		if err != ErrInvalidAddress {
			t.Errorf("err = %v, want %v", err, ErrInvalidAddress)
		}
	})

	t.Run("TruncatedIPv4", func(t *testing.T) {
		// Type IPv4 but only 3 bytes of address (need 4 + 2 port = 6 after type)
		_, _, _, err := ParseAddress([]byte{0x01, 192, 168, 1})
		if err != ErrInvalidAddress {
			t.Errorf("err = %v, want %v", err, ErrInvalidAddress)
		}
	})

	t.Run("TruncatedIPv6", func(t *testing.T) {
		buf := make([]byte, 10)
		buf[0] = 0x04
		_, _, _, err := ParseAddress(buf)
		if err != ErrInvalidAddress {
			t.Errorf("err = %v, want %v", err, ErrInvalidAddress)
		}
	})

	t.Run("TruncatedDomain", func(t *testing.T) {
		// Domain length says 11 but only 5 bytes follow
		_, _, _, err := ParseAddress([]byte{0x03, 11, 'h', 'e', 'l', 'l', 'o'})
		if err != ErrInvalidAddress {
			t.Errorf("err = %v, want %v", err, ErrInvalidAddress)
		}
	})
}

func TestBuildAddress(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		got := BuildAddress("192.168.1.1", 8080)
		want := []byte{0x01, 192, 168, 1, 1, 0x1F, 0x90}
		if !bytes.Equal(got, want) {
			t.Errorf("BuildAddress = %v, want %v", got, want)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		got := BuildAddress("::1", 443)
		if len(got) != 19 {
			t.Fatalf("len = %d, want 19", len(got))
		}
		if got[0] != AddrIPv6 {
			t.Errorf("type = 0x%02x, want 0x%02x", got[0], AddrIPv6)
		}
		port := binary.BigEndian.Uint16(got[17:19])
		if port != 443 {
			t.Errorf("port = %d, want 443", port)
		}
		// Verify the IP portion parses back to ::1
		ip := net.IP(got[1:17])
		if ip.String() != "::1" {
			t.Errorf("ip = %s, want ::1", ip)
		}
	})

	t.Run("Domain", func(t *testing.T) {
		got := BuildAddress("example.com", 80)
		want := []byte{0x03, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x00, 0x50}
		if !bytes.Equal(got, want) {
			t.Errorf("BuildAddress = %v, want %v", got, want)
		}
	})
}

func TestParseAddressBuildAddressRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		host string
		port uint16
	}{
		{"IPv4", "10.0.0.1", 1234},
		{"IPv6", "fe80::1", 9999},
		{"Domain", "example.org", 443},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			built := BuildAddress(tc.host, tc.port)
			host, port, _, err := ParseAddress(built)
			if err != nil {
				t.Fatalf("ParseAddress error: %v", err)
			}
			if host != tc.host {
				t.Errorf("host = %q, want %q", host, tc.host)
			}
			if port != tc.port {
				t.Errorf("port = %d, want %d", port, tc.port)
			}
		})
	}
}

func TestAuthNegotiation(t *testing.T) {
	t.Run("ValidNoAuth", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()

		s := &Server{
			timeout:     5 * time.Second,
			readTimeout: 5 * time.Second,
		}

		errCh := make(chan error, 1)
		go func() {
			errCh <- s.handleAuth(server)
		}()

		// Client sends: version 5, 1 method, no-auth
		_, err := client.Write([]byte{0x05, 0x01, 0x00})
		if err != nil {
			t.Fatalf("write error: %v", err)
		}

		// Read server response
		resp := make([]byte, 2)
		_, err = io.ReadFull(client, resp)
		if err != nil {
			t.Fatalf("read error: %v", err)
		}

		if resp[0] != 0x05 || resp[1] != 0x00 {
			t.Errorf("response = %v, want [0x05, 0x00]", resp)
		}

		if err := <-errCh; err != nil {
			t.Errorf("handleAuth returned error: %v", err)
		}
	})

	t.Run("InvalidVersion", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()

		s := &Server{
			timeout:     5 * time.Second,
			readTimeout: 5 * time.Second,
		}

		errCh := make(chan error, 1)
		go func() {
			errCh <- s.handleAuth(server)
		}()

		// Client sends version 4 instead of 5.
		// Use a goroutine because net.Pipe is synchronous and
		// handleAuth only reads 2 bytes before returning an error,
		// leaving the 3rd byte unread which would block Write.
		go func() {
			client.Write([]byte{0x04, 0x01, 0x00})
		}()

		if err := <-errCh; err != ErrUnsupportedVersion {
			t.Errorf("err = %v, want %v", err, ErrUnsupportedVersion)
		}
	})

	t.Run("NoAcceptableMethod", func(t *testing.T) {
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()

		s := &Server{
			timeout:     5 * time.Second,
			readTimeout: 5 * time.Second,
		}

		errCh := make(chan error, 1)
		go func() {
			errCh <- s.handleAuth(server)
		}()

		// Client offers only password auth (0x02), no no-auth
		_, err := client.Write([]byte{0x05, 0x01, 0x02})
		if err != nil {
			t.Fatalf("write error: %v", err)
		}

		// Server should reply with 0xFF (no acceptable method)
		resp := make([]byte, 2)
		_, err = io.ReadFull(client, resp)
		if err != nil {
			t.Fatalf("read error: %v", err)
		}
		if resp[0] != 0x05 || resp[1] != 0xFF {
			t.Errorf("response = %v, want [0x05, 0xFF]", resp)
		}

		if err := <-errCh; err != ErrNoAcceptableAuth {
			t.Errorf("err = %v, want %v", err, ErrNoAcceptableAuth)
		}
	})
}

func TestFullSOCKS5Handshake(t *testing.T) {
	// 1. Start a TCP echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	echoAddr := echoLn.Addr().(*net.TCPAddr)

	// 2. Start the SOCKS5 server using StreamHandler so we control
	// the forwarding lifecycle and avoid the blocking forward() method.
	socksServer, err := NewStreamServer("127.0.0.1:0", func(target string, clientConn net.Conn) error {
		remote, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			return err
		}
		defer remote.Close()
		defer clientConn.Close()

		// Bidirectional copy with proper shutdown
		done := make(chan struct{})
		go func() {
			io.Copy(clientConn, remote)
			close(done)
		}()
		io.Copy(remote, clientConn)
		// Client closed write side; close remote so the other goroutine finishes
		remote.Close()
		<-done
		return nil
	})
	if err != nil {
		t.Fatalf("NewStreamServer: %v", err)
	}
	defer socksServer.Close()

	go socksServer.Serve()

	socksAddr := socksServer.Addr().String()

	// 3. Connect as a SOCKS5 client
	conn, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 4. Auth negotiation: version 5, 1 method, no-auth
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		t.Fatalf("write auth: %v", err)
	}

	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		t.Fatalf("read auth resp: %v", err)
	}
	if authResp[0] != 0x05 || authResp[1] != 0x00 {
		t.Fatalf("auth resp = %v, want [5, 0]", authResp)
	}

	// 5. CONNECT request to echo server
	// VER=5, CMD=CONNECT, RSV=0, ATYP=IPv4
	req := []byte{0x05, 0x01, 0x00, 0x01}
	ip := echoAddr.IP.To4()
	req = append(req, ip...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(echoAddr.Port))
	req = append(req, portBytes...)

	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write connect: %v", err)
	}

	// Read reply (10 bytes: VER, REP, RSV, ATYP, BND.ADDR[4], BND.PORT[2])
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[0] != 0x05 {
		t.Fatalf("reply version = %d, want 5", reply[0])
	}
	if reply[1] != 0x00 {
		t.Fatalf("reply code = %d, want 0 (success)", reply[1])
	}

	// 6. Send data through the proxied connection and verify echo
	testData := []byte("Hello through SOCKS5 proxy!")
	if _, err := conn.Write(testData); err != nil {
		t.Fatalf("write data: %v", err)
	}

	echoed := make([]byte, len(testData))
	if _, err := io.ReadFull(conn, echoed); err != nil {
		t.Fatalf("read echoed data: %v", err)
	}

	if !bytes.Equal(testData, echoed) {
		t.Errorf("echoed = %q, want %q", echoed, testData)
	}

	// Close the client connection so the stream handler goroutines
	// detect EOF and terminate, allowing Server.Close() to complete.
	conn.Close()
}

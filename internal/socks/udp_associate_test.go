package socks

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseUDPAssociateTarget(t *testing.T) {
	for _, target := range []string{"127.0.0.1:12345", "[::1]:12345", "0.0.0.0:12345", "[::]:12345"} {
		if _, err := ParseUDPAssociateTarget(target); err != nil {
			t.Errorf("ParseUDPAssociateTarget(%q): %v", target, err)
		}
	}
	for _, target := range []string{"0.0.0.0:0", "127.0.0.1:0", "[::]:0", "example.com:12345", "invalid"} {
		if _, err := ParseUDPAssociateTarget(target); err == nil {
			t.Errorf("ParseUDPAssociateTarget(%q) succeeded, want error", target)
		}
	}
}

func writeUDPAssociateNoAuth(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := conn.Write([]byte{Version5, 1, AuthNone}); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("read auth response: %v", err)
	}
	if response[1] != AuthNone {
		t.Fatalf("auth method = %d, want AuthNone", response[1])
	}
}

func TestUDPAssociateRejectsWildcard(t *testing.T) {
	var handlerCalls atomic.Int32
	handler := func(string, net.Conn, *net.UDPConn) error {
		handlerCalls.Add(1)
		return nil
	}
	srv, err := NewStreamServer("127.0.0.1:0", nil, handler, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go srv.Serve()
	conn, err := net.DialTimeout("tcp", srv.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	writeUDPAssociateNoAuth(t, conn)
	if _, err := conn.Write([]byte{Version5, CmdUDP, 0x00, AddrIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != ReplyAddrNotSupported {
		t.Fatalf("reply code = %d, want %d", reply[1], ReplyAddrNotSupported)
	}
	if handlerCalls.Load() != 0 {
		t.Fatal("wildcard association reached the handler")
	}
}

func TestUDPAssociateAndClientIPv6(t *testing.T) {
	for _, network := range []string{"tcp", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			listen := "127.0.0.1:0"
			if network == "tcp6" {
				listen = "[::1]:0"
			}
			handler := func(target string, tcpConn net.Conn, udpConn *net.UDPConn) error {
				if _, err := ParseUDPAssociateTarget(target); err != nil {
					t.Errorf("invalid declared endpoint %q: %v", target, err)
				}
				_ = udpConn.Close()
				_ = tcpConn.Close()
				return nil
			}
			srv, err := NewStreamServer(listen, nil, handler, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer srv.Close()
			go srv.Serve()

			client, err := NewUDPProxyClient(srv.Addr().String(), nil)
			if err != nil {
				t.Fatalf("NewUDPProxyClient: %v", err)
			}
			defer client.Close()
			if client.relayAddr.Port == 0 {
				t.Fatal("relay port is zero")
			}
			if client.udpConn.LocalAddr().(*net.UDPAddr).Port == 0 {
				t.Fatal("client UDP port is zero")
			}
			if network == "tcp6" && client.relayAddr.IP.To4() != nil {
				t.Fatalf("relay address is %s, want IPv6", client.relayAddr.IP)
			}
		})
	}
}

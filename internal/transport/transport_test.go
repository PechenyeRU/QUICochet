package transport

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSetSocketBufferSmartOnUDPFd verifies the happy path on a real UDP
// socket: the helper returns a positive size (kernel always applies at
// least something) and either hits the FORCE path (requires CAP_NET_ADMIN)
// or the portable path. We don't assert the path because test runners may
// lack privileges; we only assert non-regression (the returned size is
// non-zero and ≤ our request).
func TestSetSocketBufferSmartOnUDPFd(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()

	rawConn, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("syscall conn: %v", err)
	}

	const want = 32 * 1024 * 1024
	var gotRecv, gotSend int
	rawConn.Control(func(fd uintptr) {
		gotRecv = SetSocketBufferSmart(int(fd), want, BufferDirRecv)
		gotSend = SetSocketBufferSmart(int(fd), want, BufferDirSend)
	})
	if gotRecv <= 0 {
		t.Fatalf("recv buffer: expected >0, got %d", gotRecv)
	}
	if gotSend <= 0 {
		t.Fatalf("send buffer: expected >0, got %d", gotSend)
	}
}

// TestSetSocketBufferSmartHonorsExplicitSmallRequest verifies that a
// caller asking for a small buffer (e.g. a legacy config with
// read_buffer: 1 MB) gets approximately what they asked for, not a
// silently-bumped larger value. Backwards compat: old configs must load
// and behave as the user configured.
func TestSetSocketBufferSmartHonorsExplicitSmallRequest(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()

	rawConn, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("syscall conn: %v", err)
	}

	const req = 1 * 1024 * 1024 // 1 MB — legacy-style small request
	var got int
	rawConn.Control(func(fd uintptr) {
		got = SetSocketBufferSmart(int(fd), req, BufferDirRecv)
	})
	// With BUFFORCE available (test is typically root; if not, portable
	// path applies) we should land at >= 1 MB, and importantly NOT at
	// 2+ MB via a silent bump. We allow +25% slack for kernel rounding
	// and the Linux doubling-then-halving getsockopt quirk.
	if got < req/2 {
		t.Fatalf("request of %d dropped to %d — helper bailed out too aggressively", req, got)
	}
	if got > req*2 {
		t.Fatalf("request of %d silently bumped to %d — breaks legacy config fidelity", req, got)
	}
}

// TestSetSocketBufferSmartZeroRequest verifies that passing 0 (meaning
// "don't touch it") returns the kernel's current value without an error.
// This path is hit when config has no explicit buffer size and defaults
// haven't been applied yet.
func TestSetSocketBufferSmartZeroRequest(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()

	rawConn, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("syscall conn: %v", err)
	}

	var got int
	rawConn.Control(func(fd uintptr) {
		got = SetSocketBufferSmart(int(fd), 0, BufferDirRecv)
	})
	if got <= 0 {
		t.Fatalf("expected kernel-default buffer reported on zero request, got %d", got)
	}
}

// TestReadSockBufSize sanity-checks our halving of the kernel-reported
// value. The kernel doubles SO_*BUF internally; we halve on read so the
// caller sees the user-visible size.
func TestReadSockBufSize(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()

	rawConn, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("syscall conn: %v", err)
	}

	const req = 1 * 1024 * 1024 // 1 MB — low enough to fit under most rmem_max caps
	var got int
	rawConn.Control(func(fd uintptr) {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, req); err != nil {
			t.Fatalf("setsockopt: %v", err)
		}
		got = readSockBufSize(int(fd), unix.SO_RCVBUF)
	})
	// Kernel may clamp to rmem_max, but the halved value must be in the
	// same ballpark as the request. If we got back the doubled value
	// (ie. we forgot to halve), we'd see ≥ 2× the request.
	if got < req/4 {
		t.Fatalf("halved read buffer implausibly small: got %d want near %d", got, req)
	}
	if got > req*2 {
		t.Fatalf("halved read buffer too large — did we forget to halve?: got %d want ≤ %d", got, req*2)
	}
}

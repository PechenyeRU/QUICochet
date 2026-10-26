//go:build linux

package quic

import (
	"errors"
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/stretchr/testify/require"
)

var (
	errGSO          = &os.SyscallError{Err: unix.EIO}
	errNotPermitted = &os.SyscallError{Syscall: "sendmsg", Err: unix.EPERM}
)

func TestForcingReceiveBufferSize(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Must be root to force change the receive buffer size")
	}

	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer c.Close()
	syscallConn, err := c.(*net.UDPConn).SyscallConn()
	require.NoError(t, err)

	const small = 256 << 10 // 256 KB
	if err := forceSetReceiveBuffer(syscallConn, small); errors.Is(err, unix.EPERM) {
		t.Skip("SO_RCVBUFFORCE is not permitted in this environment")
	}
	require.NoError(t, err)

	size, err := inspectReadBuffer(syscallConn)
	require.NoError(t, err)
	// the kernel doubles this value (to allow space for bookkeeping overhead)
	require.Equal(t, 2*small, size)

	const large = 32 << 20 // 32 MB
	if err := forceSetReceiveBuffer(syscallConn, large); errors.Is(err, unix.EPERM) {
		t.Skip("SO_RCVBUFFORCE is not permitted in this environment")
	}
	require.NoError(t, err)
	size, err = inspectReadBuffer(syscallConn)
	require.NoError(t, err)
	// the kernel doubles this value (to allow space for bookkeeping overhead)
	require.Equal(t, 2*large, size)
}

func TestForcingSendBufferSize(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Must be root to force change the send buffer size")
	}

	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer c.Close()
	syscallConn, err := c.(*net.UDPConn).SyscallConn()
	require.NoError(t, err)

	const small = 256 << 10 // 256 KB
	if err := forceSetSendBuffer(syscallConn, small); errors.Is(err, unix.EPERM) {
		t.Skip("SO_SNDBUFFORCE is not permitted in this environment")
	}
	require.NoError(t, err)

	size, err := inspectWriteBuffer(syscallConn)
	require.NoError(t, err)
	// the kernel doubles this value (to allow space for bookkeeping overhead)
	require.Equal(t, 2*small, size)

	const large = 32 << 20 // 32 MB
	if err := forceSetSendBuffer(syscallConn, large); errors.Is(err, unix.EPERM) {
		t.Skip("SO_SNDBUFFORCE is not permitted in this environment")
	}
	require.NoError(t, err)
	size, err = inspectWriteBuffer(syscallConn)
	require.NoError(t, err)
	// the kernel doubles this value (to allow space for bookkeeping overhead)
	require.Equal(t, 2*large, size)
}

func TestGSOError(t *testing.T) {
	require.True(t, isGSOError(errGSO))
	require.False(t, isGSOError(nil))
	require.False(t, isGSOError(errors.New("test")))
}

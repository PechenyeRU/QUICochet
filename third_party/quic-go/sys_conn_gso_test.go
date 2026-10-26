//go:build linux

package quic

import (
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

type gsoRecordingPacketConn struct {
	supportsGSO   bool
	writeMsgErr   error
	msgPayloads   [][]byte
	msgOOBs       [][]byte
	writePayloads [][]byte
}

func (c *gsoRecordingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}
func (c *gsoRecordingPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.writePayloads = append(c.writePayloads, append([]byte(nil), p...))
	return len(p), nil
}
func (c *gsoRecordingPacketConn) Close() error                     { return nil }
func (c *gsoRecordingPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *gsoRecordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *gsoRecordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *gsoRecordingPacketConn) SetWriteDeadline(time.Time) error { return nil }
func (c *gsoRecordingPacketConn) SupportsGSO() bool                { return c.supportsGSO }
func (c *gsoRecordingPacketConn) WriteMsgUDP(p, oob []byte, _ *net.UDPAddr) (int, int, error) {
	c.msgPayloads = append(c.msgPayloads, append([]byte(nil), p...))
	c.msgOOBs = append(c.msgOOBs, append([]byte(nil), oob...))
	if c.writeMsgErr != nil {
		return 0, 0, c.writeMsgErr
	}
	return len(p), len(oob), nil
}

func TestBasicConnGSOWithoutOOBOrECN(t *testing.T) {
	packetConn := &gsoRecordingPacketConn{supportsGSO: true}
	conn, err := wrapConn(packetConn)
	require.NoError(t, err)
	require.IsType(t, &basicConn{}, conn)
	require.True(t, conn.capabilities().GSO)
	require.False(t, conn.capabilities().ECN)

	payload := make([]byte, 1500)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
	n, err := conn.WritePacket(payload, addr, []byte{0xde, 0xad, 0xbe, 0xef}, 1200, protocol.ECNUnsupported)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	require.Len(t, packetConn.msgPayloads, 1)
	require.Equal(t, payload, packetConn.msgPayloads[0])
	require.Equal(t, appendUDPSegmentSizeMsg(nil, 1200), packetConn.msgOOBs[0])
	require.Empty(t, packetConn.writePayloads)
}

func TestBasicConnGSOCapabilityOptional(t *testing.T) {
	packetConn := &gsoRecordingPacketConn{}
	conn, err := wrapConn(packetConn)
	require.NoError(t, err)
	require.False(t, conn.capabilities().GSO)
	require.False(t, conn.capabilities().ECN)

	// A batch queued before the capability changed still reaches the adapter.
	_, err = conn.WritePacket(make([]byte, 1500), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1)}, nil, 1200, protocol.ECNUnsupported)
	require.NoError(t, err)
	require.Len(t, packetConn.msgPayloads, 1)
}

func TestBasicConnGSOErrorFallsBackWithoutPacketLoss(t *testing.T) {
	packetConn := &gsoRecordingPacketConn{supportsGSO: true, writeMsgErr: errGSO}
	basic := &basicConn{PacketConn: packetConn}
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
	conn := newSendConn(basic, addr, packetInfo{}, utils.DefaultLogger)
	payload := make([]byte, 2700)
	for i := range payload {
		payload[i] = byte(i)
	}

	require.NoError(t, conn.Write(payload, 1200, protocol.ECNUnsupported))
	require.False(t, conn.capabilities().GSO)
	require.Len(t, packetConn.msgPayloads, 1)
	require.Len(t, packetConn.writePayloads, 3)
	require.Len(t, packetConn.writePayloads[0], 1200)
	require.Len(t, packetConn.writePayloads[1], 1200)
	require.Len(t, packetConn.writePayloads[2], 300)
	joined := append(append(append([]byte(nil), packetConn.writePayloads[0]...), packetConn.writePayloads[1]...), packetConn.writePayloads[2]...)
	require.Equal(t, payload, joined)
}

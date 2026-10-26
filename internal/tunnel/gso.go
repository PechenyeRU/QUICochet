package tunnel

import (
	"encoding/binary"
	"errors"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

const udpSegmentDataSize = 2

type gsoPacketConn interface {
	gsoTransport
	writeMsgUDPGSO(p, oob []byte, gsoSize uint16, addr *net.UDPAddr) (n, oobn int, err error)
}

func parseUDPSegmentSize(oob []byte) (uint16, error) {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0, err
	}
	for _, message := range messages {
		if message.Header.Level != unix.IPPROTO_UDP || message.Header.Type != unix.UDP_SEGMENT {
			continue
		}
		if len(message.Data) != udpSegmentDataSize {
			return 0, errors.New("invalid UDP_SEGMENT size")
		}
		size := binary.NativeEndian.Uint16(message.Data)
		if size == 0 {
			return 0, errors.New("zero UDP_SEGMENT size")
		}
		return size, nil
	}
	return 0, errors.New("missing UDP_SEGMENT control message")
}

func makeUDPSegmentMsg(size uint16) []byte {
	oob := make([]byte, unix.CmsgSpace(udpSegmentDataSize))
	h := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	h.Level = unix.IPPROTO_UDP
	h.Type = unix.UDP_SEGMENT
	h.SetLen(unix.CmsgLen(udpSegmentDataSize))
	offset := unix.CmsgLen(0)
	binary.NativeEndian.PutUint16(oob[offset:offset+udpSegmentDataSize], size)
	return oob
}

func forEachUDPSegment(payload []byte, gsoSize uint16, send func([]byte) error) error {
	for len(payload) > 0 {
		segmentLen := min(len(payload), int(gsoSize))
		if err := send(payload[:segmentLen]); err != nil {
			return err
		}
		payload = payload[segmentLen:]
	}
	return nil
}

package spooftester

import (
	"fmt"
	"strings"
)

// Proto enumerates the L4/L3 frame types the spoof-tester can craft
// and listen for. Names mirror config.TransportType where they
// overlap so users see the same vocabulary.
type Proto string

const (
	ProtoTCP    Proto = "tcp"
	ProtoUDP    Proto = "udp"
	ProtoICMP   Proto = "icmp"
	ProtoICMPv6 Proto = "icmpv6" // proto-58-over-IPv4 trick (NOT real IPv6)
)

// ParseProto canonicalises operator-supplied flag values.
func ParseProto(s string) (Proto, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "tcp":
		return ProtoTCP, nil
	case "udp":
		return ProtoUDP, nil
	case "icmp":
		return ProtoICMP, nil
	case "icmpv6":
		return ProtoICMPv6, nil
	default:
		return "", fmt.Errorf("unknown proto %q (want tcp|udp|icmp|icmpv6)", s)
	}
}

// AllProtos returns the canonical list, useful for help output.
func AllProtos() []Proto {
	return []Proto{ProtoTCP, ProtoUDP, ProtoICMP, ProtoICMPv6}
}

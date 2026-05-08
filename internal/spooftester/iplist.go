// Package spooftester provides a probe tool that helps an operator
// figure out which source IPs are actually allowed to leave the local
// network unfiltered (i.e. spoofable from this vantage point) and
// reach a given remote endpoint.
//
// It runs as two cooperating instances:
//
//   - sender:   takes a candidate src list and sprays N packets per IP
//               at the receiver, each tagged with a magic payload.
//   - receiver: listens on the agreed proto+port, filters packets by
//               magic, and tallies which src IPs actually arrived.
//
// The output of the receiver (a JSON array of pass IPs) can be pasted
// directly into a quiccochet config under spoof.source_ips.
package spooftester

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
)

// ParseIPList reads a candidate list file and expands every line into
// a flat slice of IPs. Supported entry shapes:
//
//   1.2.3.4                 single IPv4
//   2001:db8::1             single IPv6
//   1.2.3.0/24              CIDR (network + broadcast skipped, RFC 3021)
//   2001:db8::/126          CIDR v6 (only first 64k entries are kept
//                                    for /66 and shorter to avoid OOM)
//   1.2.3.4-1.2.3.10        inclusive range, v4 only
//
// Lines starting with '#' and blank lines are ignored. Duplicates are
// removed while preserving first-seen order, mirroring the reference
// Python implementation operators are used to.
func ParseIPList(path string) ([]netip.Addr, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := make(map[netip.Addr]struct{}, 256)
	out := make([]netip.Addr, 0, 256)
	add := func(a netip.Addr) {
		if !a.IsValid() {
			return
		}
		// netip.Addr already canonicalises 4in6 to v4, so dedupe is
		// stable across "1.2.3.4" and "::ffff:1.2.3.4" entries.
		a = a.Unmap()
		if _, ok := seen[a]; ok {
			return
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineno := 0
	for sc.Scan() {
		lineno++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		ips, err := parseEntry(line)
		if err != nil {
			fmt.Fprintf(os.Stderr, "spoof-tester: line %d: skipping invalid entry %q: %v\n", lineno, line, err)
			continue
		}
		for _, ip := range ips {
			add(ip)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(out) == 0 {
		return nil, errors.New("no valid IPs found in list")
	}
	return out, nil
}

// parseEntry expands a single textual entry (one line, already trimmed
// and non-comment) into one or more netip.Addr values.
func parseEntry(s string) ([]netip.Addr, error) {
	if strings.Contains(s, "/") {
		return expandCIDR(s)
	}
	if i := strings.Index(s, "-"); i > 0 && !strings.Contains(s, ":") {
		// v4 range: only allow when the entry has no ':' (avoid matching
		// the '-' inside an IPv6 address, though netip already rejects
		// any '-' in v6 textual form, so this is belt-and-braces).
		return expandV4Range(s[:i], s[i+1:])
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return nil, err
	}
	return []netip.Addr{a}, nil
}

// expandCIDR walks every host address in the prefix. For v4 we skip
// network and broadcast as the Python tester does (Python's
// network.hosts() helper).
//
// For v6 there is no broadcast and the address space is too large for
// arbitrary masks, so we cap the expansion at expandLimit entries; the
// caller gets an error if the prefix is wider than that. Operators
// who want a real wide v6 sweep should provide explicit list lines.
func expandCIDR(s string) ([]netip.Addr, error) {
	prefix, err := netip.ParsePrefix(s)
	if err != nil {
		return nil, err
	}
	prefix = prefix.Masked()
	addr := prefix.Addr()
	bits := prefix.Bits()
	totalBits := addr.BitLen() // 32 or 128

	hostBits := totalBits - bits
	if hostBits < 0 {
		return nil, fmt.Errorf("invalid prefix %s", s)
	}

	if hostBits == 0 {
		return []netip.Addr{addr}, nil
	}

	// Cap to a sane upper bound so a /8 v4 or /48 v6 doesn't OOM the box.
	const expandLimit = 1 << 16 // 65536 entries
	count := uint64(1) << uint(hostBits)
	skipEdges := addr.Is4() && hostBits >= 2
	if count > expandLimit {
		return nil, fmt.Errorf("prefix %s expands to %d addresses, max allowed is %d (split it manually)",
			s, count, expandLimit)
	}

	out := make([]netip.Addr, 0, count)
	cur := addr
	for i := range count {
		if skipEdges && (i == 0 || i == count-1) {
			cur = cur.Next()
			continue
		}
		out = append(out, cur)
		cur = cur.Next()
	}
	return out, nil
}

// expandV4Range turns "1.2.3.4-1.2.3.10" (inclusive on both ends) into
// the corresponding addr slice. Order is preserved, the 'to' end
// must be >= 'from' and on the same family.
func expandV4Range(fromS, toS string) ([]netip.Addr, error) {
	from, err := netip.ParseAddr(strings.TrimSpace(fromS))
	if err != nil {
		return nil, fmt.Errorf("range start: %w", err)
	}
	to, err := netip.ParseAddr(strings.TrimSpace(toS))
	if err != nil {
		return nil, fmt.Errorf("range end: %w", err)
	}
	if !from.Is4() || !to.Is4() {
		return nil, errors.New("ranges supported only for IPv4")
	}

	fromN := v4ToUint32(from)
	toN := v4ToUint32(to)
	if toN < fromN {
		return nil, errors.New("range end is lower than range start")
	}
	if toN-fromN > 1<<16 {
		return nil, fmt.Errorf("range spans %d addresses, max is %d", toN-fromN, 1<<16)
	}
	out := make([]netip.Addr, 0, toN-fromN+1)
	for n := fromN; n <= toN; n++ {
		out = append(out, uint32ToV4(n))
		if n == ^uint32(0) {
			break // overflow guard
		}
	}
	return out, nil
}

func v4ToUint32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32ToV4(n uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

// AddrToNetIP converts a netip.Addr to a net.IP for callers that still
// need the legacy interface (e.g. raw socket sendto).
func AddrToNetIP(a netip.Addr) net.IP {
	if a.Is4() {
		b := a.As4()
		return net.IP(b[:])
	}
	b := a.As16()
	return net.IP(b[:])
}

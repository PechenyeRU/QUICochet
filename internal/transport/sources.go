package transport

// parseSourceLists builds the per-family multi-spoof source IP lists
// from a Config. Plural form (SourceIPs / SourceIPv6s) wins; singular
// (SourceIP / SourceIPv6) is used as a fallback.
//
// Returns ([4]byte slice for v4, [16]byte slice for v6). v4-mapped
// IPv6 entries in the v6 list are silently dropped — those should be
// configured via the v4 list.
func parseSourceLists(cfg *Config) (srcs4 [][4]byte, srcs6 [][16]byte) {
	if len(cfg.SourceIPs) > 0 {
		srcs4 = make([][4]byte, 0, len(cfg.SourceIPs))
		for _, ip := range cfg.SourceIPs {
			if v4 := ip.To4(); v4 != nil {
				var a [4]byte
				copy(a[:], v4)
				srcs4 = append(srcs4, a)
			}
		}
	} else if cfg.SourceIP != nil {
		if v4 := cfg.SourceIP.To4(); v4 != nil {
			var a [4]byte
			copy(a[:], v4)
			srcs4 = [][4]byte{a}
		}
	}

	if len(cfg.SourceIPv6s) > 0 {
		srcs6 = make([][16]byte, 0, len(cfg.SourceIPv6s))
		for _, ip := range cfg.SourceIPv6s {
			if v6 := ip.To16(); v6 != nil && ip.To4() == nil {
				var a [16]byte
				copy(a[:], v6)
				srcs6 = append(srcs6, a)
			}
		}
	} else if cfg.SourceIPv6 != nil {
		if v6 := cfg.SourceIPv6.To16(); v6 != nil && cfg.SourceIPv6.To4() == nil {
			var a [16]byte
			copy(a[:], v6)
			srcs6 = [][16]byte{a}
		}
	}
	return srcs4, srcs6
}

// parsePeerSpoofSets builds the per-family receive-side peer-spoof
// IP filter sets from a Config. Empty result = filter disabled for
// that family (legacy single-stack behaviour). Callers that enforce
// dual-stack symmetric-spoof must check both lengths themselves
// (see assertSymmetricPeerSpoof).
func parsePeerSpoofSets(cfg *Config) (set4 map[[4]byte]struct{}, set6 map[[16]byte]struct{}) {
	if len(cfg.PeerSpoofIPs) > 0 {
		set4 = make(map[[4]byte]struct{}, len(cfg.PeerSpoofIPs))
		for _, ip := range cfg.PeerSpoofIPs {
			if v4 := ip.To4(); v4 != nil {
				var key [4]byte
				copy(key[:], v4)
				set4[key] = struct{}{}
			}
		}
	} else if cfg.PeerSpoofIP != nil {
		if v4 := cfg.PeerSpoofIP.To4(); v4 != nil {
			var key [4]byte
			copy(key[:], v4)
			set4 = map[[4]byte]struct{}{key: {}}
		}
	}

	if len(cfg.PeerSpoofIPv6s) > 0 {
		set6 = make(map[[16]byte]struct{}, len(cfg.PeerSpoofIPv6s))
		for _, ip := range cfg.PeerSpoofIPv6s {
			if v6 := ip.To16(); v6 != nil && ip.To4() == nil {
				var key [16]byte
				copy(key[:], v6)
				set6[key] = struct{}{}
			}
		}
	} else if cfg.PeerSpoofIPv6 != nil {
		if v6 := cfg.PeerSpoofIPv6.To16(); v6 != nil && cfg.PeerSpoofIPv6.To4() == nil {
			var key [16]byte
			copy(key[:], v6)
			set6 = map[[16]byte]struct{}{key: {}}
		}
	}
	return set4, set6
}

// assertSymmetricPeerSpoof returns a non-nil error when the operator
// configured a peer-spoof filter on one family but not the other in
// dual-stack mode. The asymmetric configuration silently leaves the
// unfiltered family open to off-path injection because an empty set
// disables the filter — fail closed at init.
//
// transportName is interpolated into the error message so the operator
// sees which transport refused.
func assertSymmetricPeerSpoof(transportName string, dualStack bool, set4 map[[4]byte]struct{}, set6 map[[16]byte]struct{}) error {
	if !dualStack {
		return nil
	}
	v4 := len(set4) > 0
	v6 := len(set6) > 0
	if v4 == v6 {
		return nil
	}
	return symmetricPeerSpoofError(transportName)
}

// symmetricPeerSpoofError builds the canonical error message used by
// assertSymmetricPeerSpoof. Kept as a separate function so individual
// transport tests can match against the wording without coupling to
// the exact phrase across files.
func symmetricPeerSpoofError(transportName string) error {
	return &symmetricPeerSpoofErr{transport: transportName}
}

type symmetricPeerSpoofErr struct{ transport string }

func (e *symmetricPeerSpoofErr) Error() string {
	return e.transport + " transport dual-stack requires symmetric peer-spoof config: " +
		"either configure peer_spoof_ip(s) AND peer_spoof_ipv6(s), or neither, " +
		"otherwise one family is left unfiltered"
}

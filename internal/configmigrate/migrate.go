// Package configmigrate provides a v1.x → v2.x config migrator for QUICochet.
//
// Breaking changes in v2.0.0 (commit 79f46d9):
//
//  1. Server mode: top-level crypto.peer_public_key + spoof.client_real_ip[v6]
//     are moved into a single-element peers[0] entry (name "vpn1").
//
//  2. Singular spoof fields renamed to plural arrays (both modes):
//     - spoof.source_ip       → spoof.source_ips[]
//     - spoof.source_ipv6     → spoof.source_ipv6s[]
//     - spoof.peer_spoof_ip   → spoof.peer_spoof_ips[]
//     - spoof.peer_spoof_ipv6 → spoof.peer_spoof_ipv6s[]
//
// MigrateV1ToV2 is a pure function with no I/O; it never modifies fields
// that are not part of the v1→v2 break. Unknown / future fields survive
// the round-trip verbatim.
package configmigrate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// MigrateV1ToV2 converts v1.x config JSON bytes to v2.x format.
//
// Returns:
//   - out: the migrated JSON (2-space indent, trailing newline).
//   - changed: true if any v1 field was found and rewritten.
//   - err: non-nil on JSON parse failure or internal encoding error.
//
// Validation against config.Config is the caller's responsibility.
func MigrateV1ToV2(in []byte) (out []byte, changed bool, err error) {
	root, err := parseOrdered(in)
	if err != nil {
		return nil, false, fmt.Errorf("parse config JSON: %w", err)
	}

	mode := stringField(root, "mode")
	lf := detectLegacy(root, mode)

	if !lf.any() {
		// Already v2: canonicalise whitespace and return.
		buf, encErr := marshalOrdered(root)
		if encErr != nil {
			return nil, false, fmt.Errorf("re-encode config: %w", encErr)
		}
		return appendNewline(buf), false, nil
	}

	// Order matters:
	//   1. Build peers[0] BEFORE touching the spoof block (we need the
	//      legacy spoof values to copy into the peer).
	//   2. Then rename singular spoof fields → plural arrays and drop
	//      client_real_ip[v6] from spoof.
	if mode == "server" {
		applyServerPeer(&root, lf)
	}
	applySpoof(root, lf)

	buf, encErr := marshalOrdered(root)
	if encErr != nil {
		return nil, false, fmt.Errorf("encode migrated config: %w", encErr)
	}
	return appendNewline(buf), true, nil
}

// ─── legacy detection ─────────────────────────────────────────────────────────

type legacyFlags struct {
	sourceIP       bool
	sourceIPv6     bool
	peerSpoofIP    bool
	peerSpoofIPv6  bool
	clientRealIP   bool
	clientRealIPv6 bool
	cryptoPeerKey  bool
}

func (f legacyFlags) any() bool {
	return f.sourceIP || f.sourceIPv6 || f.peerSpoofIP || f.peerSpoofIPv6 ||
		f.clientRealIP || f.clientRealIPv6 || f.cryptoPeerKey
}

func detectLegacy(root orderedMap, mode string) legacyFlags {
	var f legacyFlags
	spoof := nestedMap(root, "spoof")
	f.sourceIP = hasKey(spoof, "source_ip")
	f.sourceIPv6 = hasKey(spoof, "source_ipv6")
	f.peerSpoofIP = hasKey(spoof, "peer_spoof_ip")
	f.peerSpoofIPv6 = hasKey(spoof, "peer_spoof_ipv6")
	f.clientRealIP = hasKey(spoof, "client_real_ip")
	f.clientRealIPv6 = hasKey(spoof, "client_real_ipv6")
	if mode == "server" {
		f.cryptoPeerKey = hasKey(nestedMap(root, "crypto"), "peer_public_key")
	}
	return f
}

// ─── server peer migration ────────────────────────────────────────────────────

// applyServerPeer builds peers[0] from the legacy top-level fields and
// removes crypto.peer_public_key. spoof.client_real_ip[v6] are removed by
// applySpoof afterwards.
//
// Call this BEFORE applySpoof so the spoof block still contains the
// singular/legacy values we need to copy into the peer entry.
func applyServerPeer(root *orderedMap, lf legacyFlags) {
	// Only inject peers[0] when the input has no peers array yet.
	if len(peersSlice(*root)) > 0 {
		// Already has peers — just clean up top-level crypto key.
		if lf.cryptoPeerKey {
			removeCryptoPeerKey(*root)
		}
		return
	}

	spoof := nestedMap(*root, "spoof")

	var peerPublicKey string
	if lf.cryptoPeerKey {
		peerPublicKey = rawStringValue(nestedMap(*root, "crypto"), "peer_public_key")
	}

	var clientRealIP, clientRealIPv6 string
	if lf.clientRealIP {
		clientRealIP = rawStringValue(spoof, "client_real_ip")
	}
	if lf.clientRealIPv6 {
		clientRealIPv6 = rawStringValue(spoof, "client_real_ipv6")
	}

	// Spoof arrays: try plural first, fall back to singular so we get the
	// full list regardless of which form was used.
	sourceIPs := coalesceStringSlice(spoof, "source_ips", "source_ip")
	sourceIPv6s := coalesceStringSlice(spoof, "source_ipv6s", "source_ipv6")
	peerSpoofIPs := coalesceStringSlice(spoof, "peer_spoof_ips", "peer_spoof_ip")
	peerSpoofIPv6s := coalesceStringSlice(spoof, "peer_spoof_ipv6s", "peer_spoof_ipv6")

	// Build the peers[0] entry.
	peer := orderedMap{
		{Key: "name", Value: json.RawMessage(`"vpn1"`)},
	}
	if peerPublicKey != "" {
		raw, _ := json.Marshal(peerPublicKey)
		peer = append(peer, keyValue{Key: "peer_public_key", Value: json.RawMessage(raw)})
	}
	if clientRealIP != "" {
		raw, _ := json.Marshal(clientRealIP)
		peer = append(peer, keyValue{Key: "client_real_ip", Value: json.RawMessage(raw)})
	}
	if clientRealIPv6 != "" {
		raw, _ := json.Marshal(clientRealIPv6)
		peer = append(peer, keyValue{Key: "client_real_ipv6", Value: json.RawMessage(raw)})
	}
	if len(sourceIPs) > 0 {
		raw, _ := json.Marshal(sourceIPs)
		peer = append(peer, keyValue{Key: "source_ips", Value: json.RawMessage(raw)})
	}
	if len(sourceIPv6s) > 0 {
		raw, _ := json.Marshal(sourceIPv6s)
		peer = append(peer, keyValue{Key: "source_ipv6s", Value: json.RawMessage(raw)})
	}
	if len(peerSpoofIPs) > 0 {
		raw, _ := json.Marshal(peerSpoofIPs)
		peer = append(peer, keyValue{Key: "peer_spoof_ips", Value: json.RawMessage(raw)})
	}
	if len(peerSpoofIPv6s) > 0 {
		raw, _ := json.Marshal(peerSpoofIPv6s)
		peer = append(peer, keyValue{Key: "peer_spoof_ipv6s", Value: json.RawMessage(raw)})
	}

	setPeers(root, []orderedMap{peer})

	if lf.cryptoPeerKey {
		removeCryptoPeerKey(*root)
	}
}

func removeCryptoPeerKey(root orderedMap) {
	cryptoIdx := indexOfKey(root, "crypto")
	if cryptoIdx < 0 {
		return
	}
	cm, ok := root[cryptoIdx].Value.(orderedMap)
	if !ok {
		return
	}
	deleteKey(&cm, "peer_public_key")
	root[cryptoIdx] = keyValue{Key: "crypto", Value: cm}
}

// ─── spoof migration ──────────────────────────────────────────────────────────

// applySpoof renames singular spoof fields → plural arrays and removes
// server-only fields (client_real_ip[v6]) that have been moved to peers[0].
func applySpoof(root orderedMap, lf legacyFlags) {
	spoofIdx := indexOfKey(root, "spoof")
	if spoofIdx < 0 {
		return
	}
	sm, ok := root[spoofIdx].Value.(orderedMap)
	if !ok {
		return
	}

	// Singular → plural pairs.
	type pair struct {
		singular string
		plural   string
		present  bool
	}
	pairs := []pair{
		{"source_ip", "source_ips", lf.sourceIP},
		{"source_ipv6", "source_ipv6s", lf.sourceIPv6},
		{"peer_spoof_ip", "peer_spoof_ips", lf.peerSpoofIP},
		{"peer_spoof_ipv6", "peer_spoof_ipv6s", lf.peerSpoofIPv6},
	}
	for _, p := range pairs {
		if p.present {
			mergeIntoPlural(&sm, p.singular, p.plural)
		}
	}

	// Remove fields moved to peers[0].
	if lf.clientRealIP {
		deleteKey(&sm, "client_real_ip")
	}
	if lf.clientRealIPv6 {
		deleteKey(&sm, "client_real_ipv6")
	}

	root[spoofIdx] = keyValue{Key: "spoof", Value: sm}
}

// mergeIntoPlural merges the singular string value into the plural []string,
// with singular first and deduplication. Removes the singular key.
func mergeIntoPlural(m *orderedMap, singularKey, pluralKey string) {
	singularVal := rawStringValue(*m, singularKey)
	existing := stringSliceValue(*m, pluralKey)
	merged := prependDedup(singularVal, existing)

	raw, _ := json.Marshal(merged)
	rawMsg := json.RawMessage(raw)

	pluralIdx := indexOfKey(*m, pluralKey)
	singularIdx := indexOfKey(*m, singularKey)

	if pluralIdx >= 0 {
		// Plural key exists: update it and delete singular.
		(*m)[pluralIdx] = keyValue{Key: pluralKey, Value: rawMsg}
		deleteKey(m, singularKey)
	} else if singularIdx >= 0 {
		// Only singular exists: replace it in-place with the plural key.
		(*m)[singularIdx] = keyValue{Key: pluralKey, Value: rawMsg}
	}
}

// ─── ordered JSON ─────────────────────────────────────────────────────────────

// keyValue holds one JSON object field, preserving insertion order.
type keyValue struct {
	Key   string
	Value any // orderedMap | []orderedMap | json.RawMessage
}

// orderedMap is a slice of keyValue pairs representing a JSON object.
// It preserves field order across parse → mutate → encode round-trips.
type orderedMap []keyValue

// parseOrdered parses a JSON object into an orderedMap, recursing into nested
// objects. Arrays and scalar leaves are kept as json.RawMessage.
func parseOrdered(data []byte) (orderedMap, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("expected JSON object, got %T", tok)
	}
	return parseObject(dec)
}

func parseObject(dec *json.Decoder) (orderedMap, error) {
	var m orderedMap
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("expected string key, got %T", keyTok)
		}

		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) > 0 && trimmed[0] == '{' {
			nested, err := parseOrdered(raw)
			if err != nil {
				return nil, err
			}
			m = append(m, keyValue{Key: key, Value: nested})
		} else {
			m = append(m, keyValue{Key: key, Value: raw})
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return m, nil
}

// marshalOrdered encodes an orderedMap to JSON with 2-space indentation.
func marshalOrdered(m orderedMap) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeObject(&buf, m, 0); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encodeObject(buf *bytes.Buffer, m orderedMap, depth int) error {
	indent := strings.Repeat("  ", depth)
	childIndent := strings.Repeat("  ", depth+1)

	buf.WriteByte('{')
	for i, kv := range m {
		buf.WriteByte('\n')
		buf.WriteString(childIndent)
		keyBytes, _ := json.Marshal(kv.Key)
		buf.Write(keyBytes)
		buf.WriteString(": ")

		switch v := kv.Value.(type) {
		case orderedMap:
			if err := encodeObject(buf, v, depth+1); err != nil {
				return err
			}
		case []orderedMap:
			if err := encodeObjectArray(buf, v, depth+1); err != nil {
				return err
			}
		case json.RawMessage:
			formatted, err := reindentRaw(v, depth+1)
			if err != nil {
				return err
			}
			buf.Write(formatted)
		default:
			b, err := json.Marshal(v)
			if err != nil {
				return err
			}
			buf.Write(b)
		}

		if i < len(m)-1 {
			buf.WriteByte(',')
		}
	}
	if len(m) > 0 {
		buf.WriteByte('\n')
		buf.WriteString(indent)
	}
	buf.WriteByte('}')
	return nil
}

// encodeObjectArray encodes a []orderedMap as a JSON array of objects with
// proper indentation, preserving field order within each object.
//
// depth is passed as parent's depth+1 (the value's effective depth level).
// Items are written one more level deeper so the layout matches:
//
//	"key": [       <- written by the parent encodeObject
//	  {            <- depth levels of indent
//	    "field": …  <- depth+1 levels
//	  }            <- depth levels
//	]              <- depth-1 levels (parent key's depth)
//
// encodeObjectArray encodes a []orderedMap as a JSON array.
// depth is passed as parent's (encodeObject's) depth+1.
// Example at root level (parent depth=0, depth arg=1):
//
//	"peers": [
//	    {                 <- 4 spaces = (depth+1)*2
//	      "name": "v"   <- 6 spaces = (depth+2)*2
//	    }                <- 4 spaces
//	  ]                  <- 2 spaces = depth*2
func encodeObjectArray(buf *bytes.Buffer, items []orderedMap, depth int) error {
	itemIndent := strings.Repeat("  ", depth+1)
	closeIndent := strings.Repeat("  ", depth)

	buf.WriteByte('[')
	for i, item := range items {
		buf.WriteByte('\n')
		buf.WriteString(itemIndent)
		if err := encodeObject(buf, item, depth+1); err != nil {
			return err
		}
		if i < len(items)-1 {
			buf.WriteByte(',')
		}
	}
	if len(items) > 0 {
		buf.WriteByte('\n')
		buf.WriteString(closeIndent)
	}
	buf.WriteByte(']')
	return nil
}

// reindentRaw pretty-prints a json.RawMessage at the given depth.
// Scalars and null pass through unchanged. Arrays/objects are
// re-encoded with 2-space indentation.
func reindentRaw(raw json.RawMessage, depth int) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return raw, nil
	}
	if trimmed[0] != '[' && trimmed[0] != '{' {
		return trimmed, nil
	}

	// Decode via generic interface to get a stable round-trip.
	var v any
	if err := json.Unmarshal(trimmed, &v); err != nil {
		return trimmed, nil
	}

	prefix := strings.Repeat("  ", depth)
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetIndent(prefix, "  ")
	if err := enc.Encode(v); err != nil {
		return trimmed, nil
	}
	// json.Encoder appends a newline and leading prefix. We want just the
	// content so the caller can place it inline.
	result := bytes.TrimRight(out.Bytes(), "\n")
	// Strip the leading prefix that SetIndent added to the first line —
	// the caller has already written the field key + ": " at the right depth.
	result = bytes.TrimPrefix(result, []byte(prefix))
	return result, nil
}

func appendNewline(b []byte) []byte {
	if len(b) == 0 || b[len(b)-1] != '\n' {
		return append(b, '\n')
	}
	return b
}

// ─── orderedMap helpers ───────────────────────────────────────────────────────

func indexOfKey(m orderedMap, key string) int {
	for i, kv := range m {
		if kv.Key == key {
			return i
		}
	}
	return -1
}

func hasKey(m orderedMap, key string) bool {
	return indexOfKey(m, key) >= 0
}

func deleteKey(m *orderedMap, key string) {
	idx := indexOfKey(*m, key)
	if idx < 0 {
		return
	}
	*m = append((*m)[:idx], (*m)[idx+1:]...)
}

func nestedMap(m orderedMap, key string) orderedMap {
	idx := indexOfKey(m, key)
	if idx < 0 {
		return nil
	}
	if nm, ok := m[idx].Value.(orderedMap); ok {
		return nm
	}
	return nil
}

func stringField(m orderedMap, key string) string {
	idx := indexOfKey(m, key)
	if idx < 0 {
		return ""
	}
	switch v := m[idx].Value.(type) {
	case json.RawMessage:
		var s string
		if err := json.Unmarshal(v, &s); err == nil {
			return s
		}
	case string:
		return v
	}
	return ""
}

func rawStringValue(m orderedMap, key string) string {
	return stringField(m, key)
}

func stringSliceValue(m orderedMap, key string) []string {
	idx := indexOfKey(m, key)
	if idx < 0 {
		return nil
	}
	raw, ok := m[idx].Value.(json.RawMessage)
	if !ok {
		return nil
	}
	var ss []string
	_ = json.Unmarshal(raw, &ss)
	return ss
}

func coalesceStringSlice(m orderedMap, pluralKey, singularKey string) []string {
	if ss := stringSliceValue(m, pluralKey); len(ss) > 0 {
		return ss
	}
	if s := rawStringValue(m, singularKey); s != "" {
		return []string{s}
	}
	return nil
}

func prependDedup(singular string, existing []string) []string {
	if singular == "" {
		return existing
	}
	seen := make(map[string]bool, len(existing)+1)
	out := make([]string, 0, len(existing)+1)
	out = append(out, singular)
	seen[singular] = true
	for _, s := range existing {
		if !seen[s] {
			out = append(out, s)
			seen[s] = true
		}
	}
	return out
}

func peersSlice(m orderedMap) []orderedMap {
	idx := indexOfKey(m, "peers")
	if idx < 0 {
		return nil
	}
	switch v := m[idx].Value.(type) {
	case []orderedMap:
		return v
	case json.RawMessage:
		var arr []json.RawMessage
		if err := json.Unmarshal(v, &arr); err != nil {
			return nil
		}
		result := make([]orderedMap, 0, len(arr))
		for _, r := range arr {
			if om, err := parseOrdered(r); err == nil {
				result = append(result, om)
			}
		}
		return result
	}
	return nil
}

func setPeers(root *orderedMap, peers []orderedMap) {
	idx := indexOfKey(*root, "peers")
	kv := keyValue{Key: "peers", Value: peers}
	if idx >= 0 {
		(*root)[idx] = kv
	} else {
		*root = append(*root, kv)
	}
}

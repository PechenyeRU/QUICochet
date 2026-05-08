// Package tui implements the interactive admin terminal UI for the
// QUICochet daemon. The package is invoked from cmd/quiccochet/ui.go
// via Run; nothing here ever runs in the daemon's own process so the
// Bubble Tea event loop cannot interfere with the QUIC main loop.
package tui

import (
	"embed"
	"encoding/json"
	"fmt"
)

//go:embed i18n/en.json
var i18nFS embed.FS

// Bundle holds the English UI strings. Kept as a struct + S() lookup
// so view code that calls b.S("home.daemon.title") doesn't have to
// hard-code copy inline; copy edits stay in one JSON file.
type Bundle struct {
	strings map[string]string
}

// NewBundle loads the embedded English JSON. The signature accepts an
// (unused) initial argument to leave room for future locales without
// requiring callers to be touched.
func NewBundle() (*Bundle, error) {
	data, err := i18nFS.ReadFile("i18n/en.json")
	if err != nil {
		return nil, fmt.Errorf("read i18n/en.json: %w", err)
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse i18n/en.json: %w", err)
	}
	return &Bundle{strings: m}, nil
}

// S returns the string for key, or the key itself if missing so the
// operator can spot a typo. Variadic args are interpolated via
// fmt.Sprintf — a translated string can therefore embed %s/%d
// placeholders just like a Go format string.
func (b *Bundle) S(key string, args ...any) string {
	v, ok := b.strings[key]
	if !ok {
		return key
	}
	if len(args) == 0 {
		return v
	}
	return fmt.Sprintf(v, args...)
}

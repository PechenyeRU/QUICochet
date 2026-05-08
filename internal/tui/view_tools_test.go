package tui

import (
	"testing"

	"github.com/pechenyeru/quiccochet/internal/tui/ipc"
)

// TestToolsKeygenPopulates confirms pressing 'k' through the
// handler produces a keypair on the toolsCtx that the view can
// then render. Catches a regression where the result was generated
// but not stored, which manifested as the panel resetting to
// "press k" on every redraw.
func TestToolsKeygenPopulates(t *testing.T) {
	app := &App{ipc: ipc.New("")}
	handled, err := app.toolsHandleKey("k")
	if !handled {
		t.Fatal("toolsHandleKey('k') returned not-handled")
	}
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	tc := app.toolsCtxRef()
	if tc == nil || tc.generated == nil {
		t.Fatal("toolsCtx.generated stayed nil after keygen")
	}
	if tc.generated.PublicKeyBase64() == "" {
		t.Error("generated public key is empty")
	}
	if tc.generated.PrivateKeyBase64() == "" {
		t.Error("generated private key is empty")
	}
}

// TestToolsHandleKeyUnknown asserts the router doesn't claim a key
// it doesn't service, so the global dispatcher gets a chance to
// run the digit-tab shortcuts and quit / refresh bindings.
func TestToolsHandleKeyUnknown(t *testing.T) {
	app := &App{ipc: ipc.New("")}
	handled, _ := app.toolsHandleKey("z")
	if handled {
		t.Error("toolsHandleKey('z') returned handled=true; expected false")
	}
}

// TestToolsKeygenAdvancesOnRepress confirms re-pressing 'k'
// produces a different keypair (each generation is fresh entropy)
// so an operator regenerating to fix a typo doesn't accidentally
// keep the previous public key on screen.
func TestToolsKeygenAdvancesOnRepress(t *testing.T) {
	app := &App{ipc: ipc.New("")}
	if _, err := app.toolsHandleKey("k"); err != nil {
		t.Fatalf("first keygen: %v", err)
	}
	first := app.toolsCtxRef().generated.PublicKeyBase64()
	if _, err := app.toolsHandleKey("k"); err != nil {
		t.Fatalf("second keygen: %v", err)
	}
	second := app.toolsCtxRef().generated.PublicKeyBase64()
	if first == second {
		t.Errorf("two consecutive keygens produced identical public keys: %s", first)
	}
}

package tunnel

import (
	"fmt"
	"testing"

	"github.com/quic-go/quic-go"
)

func TestApplyCongestionControlFactories(t *testing.T) {
	tests := []struct {
		mode     string
		wantType string
	}{
		{mode: "auto", wantType: "*congestion.bbr3Sender"},
		{mode: "bbrv3", wantType: "*congestion.bbr3Sender"},
		{mode: "bbrv1", wantType: "*congestion.BBRv1Sender"},
	}
	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			cfg := &quic.Config{InitialPacketSize: 1400}
			applyCongestionControl(cfg, tc.mode, "test")
			if cfg.Congestion == nil {
				t.Fatal("congestion factory is nil")
			}
			if got := fmt.Sprintf("%T", cfg.Congestion()); got != tc.wantType {
				t.Fatalf("factory type = %s, want %s", got, tc.wantType)
			}
		})
	}
}

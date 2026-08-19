package cli

import (
	"bytes"
	"os"
	"testing"
)

func TestEventColorEnabledHonorsExplicitModeAndNoColor(t *testing.T) {
	output := &bytes.Buffer{}
	previousNoColor, hadNoColor := os.LookupEnv("NO_COLOR")
	t.Cleanup(func() {
		if hadNoColor {
			_ = os.Setenv("NO_COLOR", previousNoColor)
			return
		}
		_ = os.Unsetenv("NO_COLOR")
	})

	if err := os.Setenv("NO_COLOR", "1"); err != nil {
		t.Fatalf("set NO_COLOR: %v", err)
	}
	for _, test := range []struct {
		name      string
		mode      string
		wantColor bool
		wantError bool
	}{
		{name: "always overrides NO_COLOR", mode: "always", wantColor: true},
		{name: "never disables color", mode: "never", wantColor: false},
		{name: "auto honors NO_COLOR", mode: "auto", wantColor: false},
		{name: "invalid mode fails", mode: "rainbow", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			gotColor, err := eventColorEnabled(test.mode, output)
			if (err != nil) != test.wantError {
				t.Fatalf("eventColorEnabled(%q) error = %v, want error=%t", test.mode, err, test.wantError)
			}
			if gotColor != test.wantColor {
				t.Errorf("eventColorEnabled(%q) color = %t, want %t", test.mode, gotColor, test.wantColor)
			}
		})
	}
	if err := os.Unsetenv("NO_COLOR"); err != nil {
		t.Fatalf("unset NO_COLOR: %v", err)
	}
	if gotColor, err := eventColorEnabled("auto", output); err != nil || gotColor {
		t.Errorf("eventColorEnabled(auto, redirected output) = (%t, %v), want (false, nil)", gotColor, err)
	}
}

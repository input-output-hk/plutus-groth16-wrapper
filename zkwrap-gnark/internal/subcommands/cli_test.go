package subcommands

import (
	"bytes"
	"strings"
	"testing"
)

// TestRun_Misuse pins the CLI's misuse contract: every error path returns
// ExitMisuse, leaves stdout empty, and produces a stderr message mentioning
// the offending input. Cases cover the three custom code paths — Run's
// unknown-subcommand dispatch, parse's missing-flag enforcement, and parse's
// no-positional-args rule — plus the behavioral contract that --max-inputs
// is rejected on prove/verify.
func TestRun_Misuse(t *testing.T) {
	cases := []struct {
		name      string
		args      []string
		wantInMsg string // substring stderr must contain
	}{
		{"unknown subcommand", []string{"frobnicate"}, "frobnicate"},
		{"no subcommand", nil, "subcommand"},
		{"setup missing flags", []string{"unsafe-setup"}, "max-inputs"},
		{"prove missing flags", []string{"prove"}, "inner"},
		{"verify missing flags", []string{"verify"}, "proof"},
		{
			"setup with positional arg",
			[]string{"unsafe-setup", "--max-inputs", "8", "--out", "/tmp/x", "leftover"},
			"positional",
		},
		{
			"prove rejects --max-inputs",
			[]string{"prove", "--inner", "/a", "--setup", "/b", "--out", "/c", "--max-inputs", "8"},
			"max-inputs",
		},
		{
			"verify rejects --max-inputs",
			[]string{"verify", "--proof", "/a", "--setup", "/b", "--max-inputs", "8"},
			"max-inputs",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(tc.args, &stdout, &stderr); code != ExitMisuse {
				t.Errorf("exit code: got %d, want %d", code, ExitMisuse)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout should be empty, got %q", stdout.String())
			}
			if !strings.Contains(stderr.String(), tc.wantInMsg) {
				t.Errorf("stderr should mention %q: %q", tc.wantInMsg, stderr.String())
			}
		})
	}
}

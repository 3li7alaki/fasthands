package claudecfg

import (
	"path/filepath"
	"strings"
	"testing"
)

// Invariant 7: capture extracts only the two optional public plan strings from OAuth.
func TestCapturePlan(t *testing.T) {
	for _, tt := range []struct{ name, fields, subscription, tier string }{
		{"present", `,"subscriptionType":"max","rateLimitTier":"default_claude_max_5x","otherToken":"extra-private"`, "max", "default_claude_max_5x"},
		{"absent", "", "", ""},
		{"wrong-case", `,"SubscriptionType":"max","RateLimitTier":"tier"`, "", ""},
		{"wrong-type", `,"subscriptionType":42,"rateLimitTier":{}`, "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			for key, value := range map[string]string{
				"HOME": root, "USER": "test-user", "CLAUDE_CONFIG_DIR": root,
				"CLAUDE_SECURESTORAGE_CONFIG_DIR": root, "FASTHANDS_HOME": root, "TZ": "UTC",
			} {
				t.Setenv(key, value)
			}
			blob := strings.TrimSuffix(credentials, "}}") + tt.fields + "}}"
			write(t, filepath.Join(root, ".credentials.json"), blob)
			write(t, filepath.Join(root, ".config.json"), identity)
			got, err := Read("linux", "/never-run")
			if err != nil || got.SubscriptionType != tt.subscription || got.RateLimitTier != tt.tier {
				t.Fatalf("wrong captured plan: %v", err)
			}
		})
	}
}

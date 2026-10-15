package accounts

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"fasthands/internal/usage"
)

// Invariant 7: plan metadata follows only a written outgoing backup, on both platforms.
func TestSwitchOutgoingPlan(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		for _, reason := range []string{"capture", "wiped", "foreign"} {
			t.Run(platform+"/"+reason, func(t *testing.T) {
				f := setupSwitch(t, platform)
				live := strings.Replace(liveLogin, `"claudeAiOauth":{`, `"claudeAiOauth":{"subscriptionType":"max","rateLimitTier":"default_claude_max_5x","unknownToken":"extra-private",`, 1)
				if reason == "wiped" {
					live = `{"claudeAiOauth":{"subscriptionType":"max","rateLimitTier":"default_claude_max_5x"}}`
				} else if reason == "foreign" {
					live = strings.Replace(targetLogin, `"claudeAiOauth":{`, `"claudeAiOauth":{"subscriptionType":"max","rateLimitTier":"default_claude_max_5x",`, 1)
				}
				f.setLive(t, []byte(live))
				result, err := f.m.Switch("b", f.loc, platform, f.security, SwitchOptions{})
				if err != nil || !result.Switched {
					t.Fatalf("switch failed: %v", err)
				}
				db, err := f.m.read()
				if err != nil {
					t.Fatal(err)
				}
				a := db.Accounts["id-a"]
				if reason == "capture" {
					if a.SubscriptionType != "max" || a.RateLimitTier != "default_claude_max_5x" {
						t.Fatal("outgoing plan was not captured")
					}
				} else if a.SubscriptionType != "" || a.RateLimitTier != "" {
					t.Fatal("protected outgoing backup changed plan metadata")
				}
				if b := db.Accounts["id-b"]; b.SubscriptionType != "" || b.RateLimitTier != "" {
					t.Fatal("target plan changed")
				}
				metadata, err := os.ReadFile(filepath.Join(f.m.Paths.State, "accounts.json"))
				if err != nil || strings.Contains(string(metadata), "private") || strings.Contains(string(metadata), "Token") {
					t.Fatal("credential field escaped into metadata")
				}
			})
		}
	}
}

// Invariant 9: successful switches mark usage only after all other locks are released.
func TestSwitchSetsUsageTime(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			f := setupSwitch(t, platform)
			oldNow := now
			t.Cleanup(func() { now = oldNow })
			now = func() time.Time {
				assertClaudeLocksReleased(t, f.loc)
				lock, err := os.OpenFile(filepath.Join(f.m.Paths.State, "accounts.lock"), os.O_RDWR, 0600)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
				if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
					t.Fatal("usage timestamp evaluated while accounts flock held")
				}
				return time.Unix(1792070000, 0)
			}
			result, err := f.m.Switch("b", f.loc, platform, f.security, SwitchOptions{})
			state, readErr := (usage.Store{Directory: f.m.Paths.State}).Read()
			if err != nil || !result.Switched || readErr != nil || state.LastSwitchAt != 1792070000 {
				t.Fatal("switch did not persist usage timestamp")
			}
			now = func() time.Time { t.Fatal("already-active switch marked usage"); return time.Time{} }
			if _, err := f.m.Switch("b", f.loc, platform, f.security, SwitchOptions{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

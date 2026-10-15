package main

import (
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"fasthands/internal/accounts"
	"fasthands/internal/claudecfg"
	"fasthands/internal/credstore"
)

// Slice 4b2 invariants 3, 5, 10: both command paths persist rotation before usage and expose no tokens.
func TestTokenRotationCommands(t *testing.T) {
	for _, targetPlatform := range []string{"linux", "darwin"} {
		for _, command := range []string{"refresh", "status"} {
			for _, mode := range []string{"human", "json"} {
				t.Run(targetPlatform+"/"+command+"/"+mode, func(t *testing.T) {
					f := setupSwitchCommand(t, targetPlatform)
					statusClock(t)
					calls, usages := 0, 0
					store := credstore.New(platform, securityPath, filepath.Join(f.fast, "credentials"))
					usageServer(t, func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Host == "token.test" {
							calls++
							body, err := io.ReadAll(r.Body)
							if err != nil || !strings.Contains(string(body), `"refresh_token":"second-refresh-private"`) || strings.Contains(string(body), "cli-refresh-private") || !strings.HasPrefix(r.UserAgent(), "fasthands/") {
								t.Error("command refreshed wrong account or lacked User-Agent")
							}
							io.WriteString(w, `{"access_token":"command-rotated-access-private","refresh_token":"command-rotated-refresh-private","expires_in":28800,"account":{"uuid":"second-id"}}`)
							return
						}
						usages++
						blob, err := store.Read("second-id")
						access, refresh, parseErr := claudecfg.OAuthTokens(blob)
						if err != nil || parseErr != nil || access != "command-rotated-access-private" || refresh != "command-rotated-refresh-private" || r.Header.Get("Authorization") != "Bearer "+access {
							t.Error("command used rotated access token before saving login")
						}
						io.WriteString(w, `{"five_hour":{"utilization":12,"resets_at":null}}`)
					})
					args := []string{command}
					if mode == "json" {
						args = append(args, "--json")
					}
					code, out, stderr := invoke(args...)
					if code != 0 || stderr != "" || calls != 1 || usages != 1 {
						t.Fatalf("command token rotation failed: %d %q %q", code, out, stderr)
					}
					if mode == "json" {
						if command == "refresh" {
							var result struct{ Results []accounts.FetchResult }
							if json.Unmarshal([]byte(out), &result) != nil || len(result.Results) != 2 || !result.Results[1].Fetched {
								t.Fatal("refresh did not report rotated usage")
							}
						} else {
							var result struct{ Accounts []statusAccount }
							if json.Unmarshal([]byte(out), &result) != nil || len(result.Accounts) != 2 || result.Accounts[1].FiveHour == nil || result.Accounts[1].FiveHour.Used != 12 || result.Accounts[1].Note != "" {
								t.Fatal("status did not display rotated usage")
							}
						}
					} else if command == "refresh" && !strings.Contains(out, "b\tfetched\n") || command == "status" && mode == "human" && !strings.Contains(out, "12%") {
						t.Fatal("human output lost rotated usage")
					}
					assertUsagePrivate(t, f, out+stderr)
				})
			}
		}
	}
}

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"fasthands/internal/accounts"
	"fasthands/internal/claudelock"
	"fasthands/internal/statehome"
	usageState "fasthands/internal/usage"
)

func usageServer(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	oldURL, oldTokenURL, oldTransport := usageURL, tokenURL, http.DefaultTransport
	usageURL, tokenURL, http.DefaultTransport = "http://usage.test", "http://token.test", usageTransport(handler)
	t.Cleanup(func() { usageURL, tokenURL, http.DefaultTransport = oldURL, oldTokenURL, oldTransport })
}

type usageTransport http.HandlerFunc

// O1 request assertions use httptest without binding a sandbox-blocked socket.
func (handler usageTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := r.Context().Err(); err != nil {
		return nil, err
	}
	response := httptest.NewRecorder()
	http.HandlerFunc(handler).ServeHTTP(response, r)
	return response.Result(), nil
}

func validUsageLogin(blob string) string {
	// Exact expiry boundaries belong to accounts tests; keep command fixtures valid beyond either package clock.
	expiry := time.Unix(statusNow, 0).AddDate(100, 0, 0).UnixMilli()
	return strings.Replace(blob, `"claudeAiOauth":{`, fmt.Sprintf(`"claudeAiOauth":{"expiresAt":%d,`, expiry), 1)
}

func assertUsagePrivate(t *testing.T, f commandSwitchFixture, output string) {
	t.Helper()
	for _, name := range []string{"accounts.json", "usage.json"} {
		data, err := os.ReadFile(filepath.Join(f.fast, "state", name))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		output += string(data)
	}
	assertOutputPrivate(t, output)
	for _, secret := range []string{"second-access-private", "second-refresh-private", "second-device-private", "distinctive-response-private", "command-rotated-access-private", "command-rotated-refresh-private"} {
		if strings.Contains(output, secret) {
			t.Fatal("usage command exposed credentials or response text")
		}
	}
}

// Slice 4b2 invariants 3, 5, 10: refresh rotates idle credentials on both backends.
func TestRefreshCommand(t *testing.T) {
	for _, targetPlatform := range []string{"linux", "darwin"} {
		t.Run(targetPlatform, func(t *testing.T) {
			f := setupSwitchCommand(t, targetPlatform)
			statusClock(t)
			f.setLive(t, validUsageLogin(activeBlob))
			for _, lock := range claudelock.Locks(f.loc) {
				if err := os.Mkdir(lock.Path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			var calls, tokenCalls atomic.Int32
			usageServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Host == "token.test" {
					tokenCalls.Add(1)
					io.WriteString(w, `{"access_token":"command-rotated-access-private","refresh_token":"command-rotated-refresh-private","expires_in":28800}`)
					return
				}
				calls.Add(1)
				if (r.Header.Get("Authorization") != "Bearer cli-access-private" && r.Header.Get("Authorization") != "Bearer command-rotated-access-private") || !strings.HasPrefix(r.UserAgent(), "fasthands/") {
					t.Error("command used wrong live token or User-Agent")
				}
				io.WriteString(w, `{"five_hour":{"utilization":12,"resets_at":null}}`)
			})
			code, out, stderr := invoke("refresh", "--json")
			var result struct {
				Results []accounts.FetchResult `json:"results"`
			}
			var shape struct {
				Results []map[string]json.RawMessage `json:"results"`
			}
			if code != 0 || stderr != "" || json.Unmarshal([]byte(out), &result) != nil || json.Unmarshal([]byte(out), &shape) != nil || len(result.Results) != 2 || calls.Load() != 2 || tokenCalls.Load() != 1 {
				t.Fatalf("refresh failed: %d %q %q", code, out, stderr)
			}
			a, b := result.Results[0], result.Results[1]
			if a.Alias != "a" || !a.Fetched || a.Error != "" || a.Skipped != "" || b.Alias != "b" || !b.Fetched || b.Skipped != "" || b.Error != "" {
				t.Fatal("refresh results differ from contract")
			}
			for _, row := range shape.Results {
				if len(row) != 5 || string(row["error"]) != `""` || row["skipped"] == nil || string(row["skipped"]) == "null" || row["accountUuid"] == nil {
					t.Fatal("wrong refresh result shape")
				}
			}
			assertUsagePrivate(t, f, out+stderr)
			if targetPlatform == "darwin" {
				data, err := os.ReadFile(filepath.Join(f.keychain, "calls"))
				if err != nil || strings.Count(string(data), f.loc.Service+"/") != 1 || strings.Count(string(data), "add-generic-password") != 2 {
					t.Fatal("refresh must read live login once and write both backup generations")
				}
			}
			code, out, stderr = invoke("refresh", "a")
			if code != 0 || out != "a\tfetched\n" || stderr != "" || calls.Load() != 3 {
				t.Fatal("wrong refresh human success output")
			}
			assertUsagePrivate(t, f, out+stderr)
		})
	}
}

// Slice 4b1 invariants 8, 10: skips exit zero; failures exit one in either mode.
func TestRefreshCommandFailures(t *testing.T) {
	for _, targetPlatform := range []string{"linux", "darwin"} {
		for _, failure := range []string{"expired", "live-unreadable", "absent", "unreadable", "server", "unauthorized", "limited"} {
			t.Run(targetPlatform+"/"+failure, func(t *testing.T) {
				f := setupSwitchCommand(t, targetPlatform)
				statusClock(t)
				f.setLive(t, validUsageLogin(activeBlob))
				alias, wantSkip, wantError, wantCode, status := "a", "", "", 0, 200
				switch failure {
				case "expired":
					f.setLive(t, activeBlob)
					wantSkip = "access token expired"
				case "live-unreadable":
					if targetPlatform == "darwin" {
						t.Setenv("FH_FAIL_READ", f.loc.Service+"/"+f.loc.KeychainAccount)
					} else if err := os.Remove(f.loc.CredentialsFile); err != nil {
						t.Fatal(err)
					}
					wantSkip = "live login unreadable"
				case "absent", "unreadable":
					alias, wantSkip = "b", "no stored login"
					path := filepath.Join(f.fast, "credentials", "second-id.json")
					if targetPlatform == "darwin" {
						path = filepath.Join(f.keychain, "fasthands", "second-id")
					}
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if failure == "unreadable" {
						wantCode, wantSkip, wantError = 1, "", "stored login for b is unreadable right now; retry, do not re-add"
						if targetPlatform == "darwin" {
							t.Setenv("FH_FAIL_READ", "fasthands/second-id")
						} else if err := os.Mkdir(path, 0700); err != nil {
							t.Fatal(err)
						}
					}
				case "server":
					wantCode, status, wantError = 1, 500, "usage request returned HTTP 500"
				case "unauthorized":
					wantCode, status, wantError = 1, 401, "access token rejected"
				case "limited":
					wantCode, status = 1, 429
				}
				calls := 0
				usageServer(t, func(w http.ResponseWriter, r *http.Request) {
					calls++
					w.WriteHeader(status)
					io.WriteString(w, "cli-access-private distinctive-response-private")
				})
				code, out, stderr := invoke("refresh", alias, "--json")
				var result struct {
					Results []accounts.FetchResult `json:"results"`
				}
				if code != wantCode || stderr != "" || json.Unmarshal([]byte(out), &result) != nil || len(result.Results) != 1 {
					t.Fatalf("wrong refresh failure shape or exit: %d %q %q", code, out, stderr)
				}
				r := result.Results[0]
				if failure == "limited" {
					if !strings.HasPrefix(r.Error, "rate limited until ") {
						t.Fatal("rate limit deadline missing")
					}
				} else if r.Skipped != wantSkip || r.Error != wantError {
					t.Fatalf("wrong failure result: %+v", r)
				}
				if (status != 200 && calls != 1) || (status == 200 && calls != 0) || r.Fetched {
					t.Fatal("unexpected HTTP request or fetched result")
				}
				assertUsagePrivate(t, f, out+stderr)
				code, out, stderr = invoke("refresh", alias)
				prefix := alias + "\tskipped: "
				if wantCode == 1 && failure != "limited" {
					prefix = alias + "\terror: "
				}
				if stderr != "" || !strings.HasPrefix(out, prefix) || (failure != "limited" && code != wantCode) || (failure == "limited" && code != 0) {
					t.Fatalf("wrong human refusal: %d %q %q", code, out, stderr)
				}
				assertUsagePrivate(t, f, out+stderr)
			})
		}
	}
}

func TestRefreshAliasesAndEmpty(t *testing.T) {
	setupActive(t)
	usageServer(t, func(w http.ResponseWriter, r *http.Request) { t.Error("empty refresh sent HTTP") })
	if code, out, stderr := invoke("refresh", "--json"); code != 0 || out != "{\"results\":[]}\n" || stderr != "" {
		t.Fatal("empty refresh must return []")
	}
	for _, args := range [][]string{{"refresh", "missing"}, {"refresh", "--json", "missing"}} {
		if code, out, stderr := invoke(args...); code != 2 || out != "" || !strings.Contains(stderr, `no account with alias "missing"`) {
			t.Fatal("unknown alias must be named and exit 2")
		}
	}
	if code, out, stderr := invoke("refresh", "--help"); code != 0 || !strings.Contains(out, "refresh [ALIAS...]") || stderr != "" {
		t.Fatal("refresh help missing")
	}
}

// Slice 4b1: selecting idle accounts never reads the live login, and aliases are deduplicated.
func TestRefreshIdleAliases(t *testing.T) {
	for _, targetPlatform := range []string{"linux", "darwin"} {
		t.Run(targetPlatform, func(t *testing.T) {
			f := setupSwitchCommand(t, targetPlatform)
			f.setLive(t, validUsageLogin(secondBlob))
			writeFixture(t, f.loc.GlobalConfig, secondIdentity)
			if code, _, stderr := invoke("add", "--alias", "b"); code != 0 {
				t.Fatal(stderr)
			}
			writeFixture(t, f.loc.GlobalConfig, activeIdentity)
			if targetPlatform == "darwin" {
				t.Setenv("FH_FAIL_READ", f.loc.Service+"/"+f.loc.KeychainAccount)
				writeFixture(t, filepath.Join(f.keychain, "calls"), "")
			} else if err := os.Remove(f.loc.CredentialsFile); err != nil {
				t.Fatal(err)
			}
			calls := 0
			usageServer(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Header.Get("Authorization") != "Bearer second-access-private" {
					t.Error("idle fetch used live credentials")
				}
				io.WriteString(w, `{}`)
			})
			code, out, stderr := invoke("refresh", "b", "--json", "b")
			if code != 0 || stderr != "" || calls != 1 || !strings.Contains(out, `"fetched":true`) {
				t.Fatal("interspersed flags or repeated alias failed")
			}
			if targetPlatform == "darwin" {
				data, err := os.ReadFile(filepath.Join(f.keychain, "calls"))
				if err != nil || string(data) != "argv find-generic-password fasthands/second-id\n" {
					t.Fatal("idle refresh read the live login")
				}
			}
			assertUsagePrivate(t, f, out+stderr)
		})
	}
}

// Slice 4b1 invariants 9, 10: only stale accounts fetch; API failures become notes, not exits.
func TestStatusFetchStale(t *testing.T) {
	for _, targetPlatform := range []string{"linux", "darwin"} {
		for _, mode := range []string{"stale", "empty", "boundary", "model-fresh", "skip", "server"} {
			t.Run(targetPlatform+"/"+mode, func(t *testing.T) {
				f := setupSwitchCommand(t, targetPlatform)
				statusClock(t)
				f.setLive(t, validUsageLogin(activeBlob))
				if mode == "skip" {
					f.setLive(t, activeBlob)
				}
				store := usageState.Store{Directory: filepath.Join(f.fast, "state")}
				state := usageState.State{SchemaVersion: 1, Sessions: map[string]usageState.Session{}, Accounts: map[string]usageState.Account{
					"12345678-1234-1234-1234-123456789abc": {Windows: usageState.Windows{FiveHour: &usageState.Window{Used: 1, SeenAt: statusNow - 601}}, Source: "statusline"},
					"second-id":                            {Windows: usageState.Windows{SevenDay: &usageState.Window{Used: 2, SeenAt: statusNow}}, Source: "statusline"},
				}}
				a := state.Accounts["12345678-1234-1234-1234-123456789abc"]
				if mode == "boundary" {
					a.FiveHour.SeenAt = statusNow - 600
				}
				if mode == "model-fresh" {
					a.Models = map[string]*usageState.Window{"Fable": {Used: 3, SeenAt: statusNow}}
				}
				state.Accounts["12345678-1234-1234-1234-123456789abc"] = a
				if mode == "empty" {
					delete(state.Accounts, "12345678-1234-1234-1234-123456789abc")
				}
				data, _ := json.Marshal(state)
				if err := statehome.AtomicWrite(filepath.Join(store.Directory, "usage.json"), data); err != nil {
					t.Fatal(err)
				}
				var calls atomic.Int32
				usageServer(t, func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.Header.Get("Authorization") != "Bearer cli-access-private" {
						t.Error("fresh account was fetched")
					}
					if mode == "server" {
						w.WriteHeader(500)
						io.WriteString(w, "cli-access-private distinctive-response-private")
						return
					}
					io.WriteString(w, `{"five_hour":{"utilization":42,"resets_at":null},"limits":[{"scope":{"model":{"display_name":"Fable"}},"percent":12,"resets_at":null}]}`)
				})
				code, out, stderr := invoke("status", "--json")
				var result struct {
					Accounts []statusAccount `json:"accounts"`
				}
				if code != 0 || stderr != "" || json.Unmarshal([]byte(out), &result) != nil || len(result.Accounts) != 2 {
					t.Fatalf("status fetch failed: %d %q %q", code, out, stderr)
				}
				row := result.Accounts[0]
				wantCalls, note := int32(0), ""
				switch mode {
				case "stale", "empty":
					wantCalls = 1
					if row.Source == nil || *row.Source != "api" || row.FiveHour.Used != 42 || row.Models["Fable"] == nil || row.Models["Fable"].Used != 12 {
						t.Fatal("status did not render fetched API windows")
					}
				case "server":
					wantCalls, note = 1, "usage request returned HTTP 500"
				case "skip":
					note = "access token expired"
				}
				if calls.Load() != wantCalls || row.Note != note || result.Accounts[1].Note != "" || result.Accounts[1].Models == nil || len(result.Accounts[1].Models) != 0 {
					t.Fatal("wrong stale selection, note or empty models shape")
				}
				assertUsagePrivate(t, f, out+stderr)
				if mode == "skip" || mode == "server" {
					code, out, stderr = invoke("status")
					if code != 0 || stderr != "" || !strings.Contains(out, "\t"+note+"\n") {
						t.Fatal("human status lost fetch note or failed")
					}
					assertUsagePrivate(t, f, out+stderr)
				}
			})
		}
	}
}

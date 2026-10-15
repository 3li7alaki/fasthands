package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"fasthands/internal/claudecfg"
	"fasthands/internal/credstore"
	"fasthands/internal/oauth"
	"fasthands/internal/picker"
	"fasthands/internal/statehome"
	usageState "fasthands/internal/usage"
)

const activeID = "12345678-1234-1234-1234-123456789abc"

func pickerUsage(t *testing.T, f commandSwitchFixture, activeUsed float64) {
	t.Helper()
	state := usageState.State{SchemaVersion: 1, Accounts: map[string]usageState.Account{
		activeID:    {Windows: usageState.Windows{SevenDay: &usageState.Window{Used: activeUsed, ResetsAt: statusNow + 20000}}},
		"second-id": {Windows: usageState.Windows{SevenDay: &usageState.Window{Used: 20, ResetsAt: statusNow + 10000}}},
	}, Sessions: map[string]usageState.Session{}}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := statehome.AtomicWrite(filepath.Join(f.fast, "state", "usage.json"), data); err != nil {
		t.Fatal(err)
	}
}

// Slice 5a invariant 9: set, print, clear unlisted ranks, reject the whole bad order, and emit [].
func TestPriorityCommand(t *testing.T) {
	_, fast := setupActive(t)
	statusClock(t)
	if code, out, stderr := invoke("priority", "--json"); code != 0 || out != "{\"priority\":[]}\n" || stderr != "" {
		t.Fatal("empty priority JSON must contain []")
	}
	if _, err := os.Stat(fast); !os.IsNotExist(err) {
		t.Fatal("reading priority created state")
	}
	f := setupSwitchCommand(t, "linux")
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"priority", "b", "--json", "a"}, "{\"priority\":[\"b\",\"a\"]}\n"},
		{[]string{"priority"}, "b\na\n"},
		{[]string{"priority", "a"}, "a\n"},
		{[]string{"priority", "--json"}, "{\"priority\":[\"a\"]}\n"},
	} {
		if code, out, stderr := invoke(tt.args...); code != 0 || out != tt.want || stderr != "" {
			t.Fatalf("priority failed: %d %q %q", code, out, stderr)
		}
	}
	before := snapshot(t, f.fast)
	for _, aliases := range [][]string{{"a", "missing"}, {"b", "b"}} {
		if code, out, stderr := invoke(append([]string{"priority"}, aliases...)...); code == 0 || out != "" || !strings.Contains(stderr, fmt.Sprintf("%q", aliases[1])) {
			t.Fatal("invalid priority did not name alias")
		}
		if !reflect.DeepEqual(before, snapshot(t, f.fast)) {
			t.Fatal("invalid priority wrote files")
		}
	}
}

// Slice 5a invariant 10: neither output mode fetches, reads credentials, nor changes any file.
func TestPickOffline(t *testing.T) {
	for _, targetPlatform := range []string{"linux", "darwin"} {
		for _, mode := range []string{"switch", "hold", "unknown"} {
			t.Run(targetPlatform+"/"+mode, func(t *testing.T) {
				f := setupSwitchCommand(t, targetPlatform)
				statusClock(t)
				pickerUsage(t, f, 92)
				if mode == "hold" {
					store := usageState.Store{Directory: filepath.Join(f.fast, "state")}
					if err := store.MarkSwitch(statusNow); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "unknown" {
					writeFixture(t, f.loc.GlobalConfig, `{"oauthAccount":{"accountUuid":"unmanaged"}}`)
				}
				usageServer(t, func(w http.ResponseWriter, r *http.Request) { t.Error("pick reached usage or token endpoint") })
				if err := os.Remove(f.loc.CredentialsFile); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
				roots := []string{f.fast, f.home}
				if targetPlatform == "darwin" {
					roots = append(roots, f.keychain)
				}
				for _, args := range [][]string{{"pick"}, {"pick", "--json"}} {
					before := make([]map[string]fileSnapshot, len(roots))
					for i, root := range roots {
						before[i] = snapshot(t, root)
					}
					code, out, stderr := invoke(args...)
					if code != 0 || stderr != "" {
						t.Fatalf("pick failed: %d %q %q", code, out, stderr)
					}
					if len(args) == 2 {
						var d picker.Decision
						var shape map[string]json.RawMessage
						if json.Unmarshal([]byte(out), &d) != nil || json.Unmarshal([]byte(out), &shape) != nil || len(shape) != 6 || string(shape["auto"]) != "true" || d.Reason == "" || d.From != map[bool]string{true: "", false: "a"}[mode == "unknown"] {
							t.Fatal("pick JSON shape or alias wrong")
						}
						if mode == "switch" && (d.Action != "switch" || d.To != "b") || mode != "switch" && (d.Action != "hold" || d.To != "") {
							t.Fatalf("wrong pick: %+v", d)
						}
					} else if mode == "switch" && !strings.HasPrefix(out, "switch a -> b: ") || mode != "switch" && !strings.HasPrefix(out, "hold: ") {
						t.Fatal("wrong human pick output")
					}
					for i, root := range roots {
						if !reflect.DeepEqual(before[i], snapshot(t, root)) {
							t.Fatal("pick wrote a file or read Keychain")
						}
					}
					assertUsagePrivate(t, f, out+stderr)
				}
			})
		}
	}
}

// Slice 5a invariant 11: another actor's flock stops before identity reads and HTTP.
func TestAutoLockHeld(t *testing.T) {
	f := setupSwitchCommand(t, "linux")
	statusClock(t)
	pickerUsage(t, f, 92)
	path := filepath.Join(f.fast, "state", "auto.lock")
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.loc.GlobalConfig); err != nil {
		t.Fatal(err)
	}
	usageServer(t, func(w http.ResponseWriter, r *http.Request) { t.Error("locked auto reached endpoint") })
	before := snapshot(t, f.fast)
	for _, args := range [][]string{{"auto", "--once"}, {"auto", "--once", "--json"}} {
		if code, out, stderr := invoke(args...); code != 0 || out != "" || stderr != "" {
			t.Fatal("locked auto must silently exit zero")
		}
	}
	if !reflect.DeepEqual(before, snapshot(t, f.fast)) {
		t.Fatal("locked auto changed state")
	}
}

// Slice 5a invariant 11: refresh only the chosen account, re-decide, force switch, and append one private log line.
func TestAutoOnce(t *testing.T) {
	for _, targetPlatform := range []string{"linux", "darwin"} {
		for _, mode := range []string{"human", "json", "hold-human", "hold-json", "rotate", "warning", "retarget", "switch-failure", "create-log", "fetch-failure"} {
			t.Run(targetPlatform+"/"+mode, func(t *testing.T) {
				f := setupSwitchCommand(t, targetPlatform)
				statusClock(t)
				pickerUsage(t, f, 92)
				store := credstore.New(platform, securityPath, filepath.Join(f.fast, "credentials"))
				if mode != "rotate" {
					if err := store.Write("second-id", []byte(validUsageLogin(secondBlob))); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "warning" {
					if err := os.Mkdir(filepath.Join(f.home, "sessions"), 0700); err != nil {
						t.Fatal(err)
					}
					writeFixture(t, filepath.Join(f.home, "sessions", "42.json"), "invalid")
				}
				if mode == "retarget" {
					f.setLive(t, validUsageLogin(secondBlob))
					writeFixture(t, f.loc.GlobalConfig, strings.Replace(secondIdentity, "second-id", "third-id", 1))
					if code, _, stderr := invoke("add", "--alias", "c"); code != 0 {
						t.Fatal(stderr)
					}
					writeFixture(t, f.loc.GlobalConfig, activeIdentity)
					f.setLive(t, activeBlob)
					if err := (usageState.Store{Directory: filepath.Join(f.fast, "state")}).SaveFetched("third-id", oauth.Usage{SevenDay: &oauth.Window{Used: 30, ResetsAt: statusNow + 15000}}, statusNow); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "switch-failure" {
					if err := store.Write("second-id", []byte(`{"claudeAiOauth":{"accessToken":"second-access-private","expiresAt":9999999999999}}`)); err != nil {
						t.Fatal(err)
					}
				}
				calls, tokens := 0, 0
				usageServer(t, func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Host == "token.test" {
						tokens++
						if mode != "rotate" {
							t.Error("unexpected token request")
						}
						io.WriteString(w, `{"access_token":"command-rotated-access-private","refresh_token":"command-rotated-refresh-private","expires_in":28800,"account":{"uuid":"second-id"}}`)
						return
					}
					calls++
					want := "Bearer second-access-private"
					if mode == "rotate" {
						want = "Bearer command-rotated-access-private"
					}
					if r.Header.Get("Authorization") != want {
						t.Error("auto refreshed another account")
					}
					// Auto's flock must remain held across refresh and the acting switch.
					other, err := autoLock(filepath.Join(f.fast, "state"))
					if err != nil || other != nil {
						if other != nil {
							other.Close()
						}
						t.Error("auto released its flock during HTTP")
					}
					if mode == "fetch-failure" {
						w.WriteHeader(500)
						io.WriteString(w, "distinctive-response-private")
						return
					}
					used, reset := 25, statusNow+10000
					if strings.HasPrefix(mode, "hold") || mode == "retarget" {
						used, reset = 95, statusNow+25000
					}
					fmt.Fprintf(w, `{"seven_day":{"utilization":%d,"resets_at":%q}}`, used, time.Unix(reset, 0).UTC().Format(time.RFC3339))
				})
				logPath := filepath.Join(f.fast, "state", "auto.log")
				// Existing logs must be appended and tightened rather than replaced.
				existing := "existing\n"
				if mode == "create-log" {
					existing = ""
				} else {
					writeFixture(t, logPath, existing)
					if err := os.Chmod(logPath, 0644); err != nil {
						t.Fatal(err)
					}
				}
				args := []string{"auto", "--once"}
				jsonMode := strings.HasSuffix(mode, "json") || mode == "rotate" || mode == "retarget" || mode == "warning"
				if jsonMode {
					args = append(args, "--json")
				}
				code, out, stderr := invoke(args...)
				if mode == "switch-failure" {
					if code != 1 || out != "" || !strings.Contains(stderr, "refresh token") {
						t.Fatal("failed switch must exit one")
					}
				} else if code != 0 || mode != "warning" && stderr != "" || mode == "warning" && !strings.Contains(stderr, "warning: 1 Claude session(s) mid-turn") {
					t.Fatalf("auto failed: %d %q %q", code, out, stderr)
				}
				wantSwitch := !strings.HasPrefix(mode, "hold") && mode != "switch-failure"
				wantAlias, wantID := "b", "second-id"
				if mode == "retarget" {
					wantAlias, wantID = "c", "third-id"
				}
				if jsonMode {
					var result struct {
						picker.Decision
						Switched bool
					}
					var shape map[string]json.RawMessage
					if json.Unmarshal([]byte(out), &result) != nil || json.Unmarshal([]byte(out), &shape) != nil || len(shape) != 6 || result.Switched != wantSwitch || result.From != "a" {
						t.Fatal("wrong auto JSON shape or switched flag")
					}
					if wantSwitch && (result.Action != "switch" || result.To != wantAlias) || !wantSwitch && (result.Action != "hold" || result.To != "") {
						t.Fatalf("auto did not use fresh decision: %+v", result)
					}
				} else if mode != "switch-failure" && (wantSwitch && !strings.HasPrefix(out, "switch a -> b: ") || !wantSwitch && !strings.HasPrefix(out, "hold: ")) {
					t.Fatal("wrong auto human output")
				}
				live, err := claudecfg.ActiveUUID(f.loc)
				if err != nil || wantSwitch && live != wantID || !wantSwitch && live != activeID {
					t.Fatal("wrong live account after auto")
				}
				log, err := os.ReadFile(logPath)
				info, statErr := os.Stat(logPath)
				if err != nil || statErr != nil {
					t.Fatal("cannot inspect auto log")
				}
				if wantSwitch {
					prefix := existing + time.Unix(statusNow, 0).UTC().Format(time.RFC3339) + "\ta\t" + wantAlias + "\t"
					if !strings.HasPrefix(string(log), prefix) || strings.Count(string(log), "\n") != strings.Count(existing, "\n")+1 || info.Mode().Perm() != 0600 {
						t.Fatal("switch did not append exactly one private UTC log line")
					}
				} else if string(log) != "existing\n" {
					t.Fatal("held or failed switch appended a log")
				}
				if calls != 1 || (mode == "rotate") != (tokens == 1) {
					t.Fatal("auto did not refresh exactly its original target")
				}
				assertUsagePrivate(t, f, out+stderr+string(log))
				for _, secret := range []string{"cli-access-private", "cli-refresh-private", "second-access-private", "second-refresh-private", "command-rotated-access-private", "command-rotated-refresh-private"} {
					if strings.Contains(string(log), secret) || strings.Contains(string(log), hex.EncodeToString([]byte(secret))) {
						t.Fatal("auto log contains credential text")
					}
				}
				if held, err := autoLock(filepath.Join(f.fast, "state")); err != nil || held == nil {
					t.Fatal("auto did not release flock")
				} else {
					held.Close()
				}
			})
		}
	}
}

func TestAutoHoldMatchesPick(t *testing.T) {
	f := setupSwitchCommand(t, "linux")
	statusClock(t)
	pickerUsage(t, f, 40)
	if err := (usageState.Store{Directory: filepath.Join(f.fast, "state")}).MarkSwitch(statusNow); err != nil {
		t.Fatal(err)
	}
	usageServer(t, func(w http.ResponseWriter, r *http.Request) { t.Error("held decision sent request") })
	_, expected, _ := invoke("pick")
	if code, out, stderr := invoke("auto", "--once"); code != 0 || out != expected || stderr != "" {
		t.Fatal("held auto differs from pick")
	}
	if code, out, stderr := invoke("auto", "--once", "--json"); code != 0 || !strings.Contains(out, `"switched":false`) || stderr != "" {
		t.Fatal("held auto JSON must say switched false")
	}
	if _, err := os.Stat(filepath.Join(f.fast, "state", "auto.log")); !os.IsNotExist(err) {
		t.Fatal("held auto created log")
	}
}

func TestPickerCommandUsageAndFailures(t *testing.T) {
	home, _ := setupActive(t)
	for _, args := range [][]string{{"pick", "extra"}, {"pick", "--json=bad"}, {"auto", ""}, {"auto", "bad"}, {"auto", "on", "off"}, {"auto", "on", "--once"}, {"auto", "--once", "off"}, {"auto", "--json=bad"}, {"auto", "--once", "extra"}, {"priority", "--unknown"}} {
		if code, out, stderr := invoke(args...); code != 2 || out != "" || stderr == "" {
			t.Fatalf("invalid arguments accepted: %v", args)
		}
	}
	for _, command := range []string{"priority", "pick", "auto"} {
		if code, out, stderr := invoke(command, "--help"); code != 0 || !strings.Contains(out, "priority [ALIAS...]") || !strings.Contains(out, "auto --once") || stderr != "" {
			t.Fatal("picker commands missing from help")
		}
	}
	if err := os.Remove(filepath.Join(home, ".config.json")); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"pick", "auto"} {
		args, want := []string{command}, 1
		if command == "auto" {
			args, want = append(args, "--once"), 0
		}
		if code, out, stderr := invoke(args...); code != want || out != "" || stderr == "" {
			t.Fatal("wrong operational failure exit code")
		}
	}
}

// A reset-chasing switch waits while any session, the caller's included, is mid-turn;
// it spends no usage request while waiting and switches once sessions are idle.
func TestAutoOnceWaitsForIdle(t *testing.T) {
	for _, targetPlatform := range []string{"linux", "darwin"} {
		for _, mode := range []string{"busy", "busy-self", "idle"} {
			t.Run(targetPlatform+"/"+mode, func(t *testing.T) {
				f := setupSwitchCommand(t, targetPlatform)
				statusClock(t)
				pickerUsage(t, f, 30) // second resets 10000s sooner: not urgent
				store := credstore.New(platform, securityPath, filepath.Join(f.fast, "credentials"))
				if err := store.Write("second-id", []byte(validUsageLogin(secondBlob))); err != nil {
					t.Fatal(err)
				}
				if mode != "idle" {
					if err := os.Mkdir(filepath.Join(f.home, "sessions"), 0700); err != nil {
						t.Fatal(err)
					}
					writeFixture(t, filepath.Join(f.home, "sessions", "42.json"), "invalid")
				}
				if mode == "busy-self" {
					t.Setenv("CLAUDE_PID", "42") // the spawning session's own turn still counts
				}
				calls := 0
				usageServer(t, func(w http.ResponseWriter, r *http.Request) {
					calls++
					fmt.Fprintf(w, `{"seven_day":{"utilization":20,"resets_at":%q}}`, time.Unix(statusNow+10000, 0).UTC().Format(time.RFC3339))
				})
				code, out, stderr := invoke("auto", "--once")
				live, err := claudecfg.ActiveUUID(f.loc)
				if err != nil || code != 0 || stderr != "" {
					t.Fatalf("auto failed: %d %q %q", code, out, stderr)
				}
				if mode == "idle" {
					if !strings.HasPrefix(out, "switch a -> b: ") || live != "second-id" || calls != 1 {
						t.Fatalf("idle sessions must not delay the switch: %q", out)
					}
					return
				}
				if out != "hold: waiting for idle Claude sessions before switching to b\n" || live != activeID || calls != 0 {
					t.Fatalf("busy sessions must hold without a usage request: %q calls=%d", out, calls)
				}
			})
		}
	}
}

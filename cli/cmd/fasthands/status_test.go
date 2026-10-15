package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"fasthands/internal/claudelock"
	"fasthands/internal/statehome"
	usageState "fasthands/internal/usage"
)

const statusNow int64 = 1792070000
const statusSample = `{"session_id":"demo","rate_limits":{"five_hour":{"used_percentage":42,"resets_at":1792080000},"seven_day":{"used_percentage":61.5,"resets_at":1792400000}}}`

func statusClock(t *testing.T) {
	t.Helper()
	t.Setenv("TZ", "UTC")
	oldNow, oldLocal := now, time.Local
	now = func() time.Time { return time.Unix(statusNow, 0) }
	time.Local = time.UTC
	t.Cleanup(func() { now, time.Local = oldNow, oldLocal })
}

func hook(t *testing.T, input string, args ...string) (int, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdin")
	writeFixture(t, path, input)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	old := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = old }()
	return invoke(append([]string{"hook", "statusline"}, args...)...)
}

// Invariant 6: hook failures stay silent, exit zero, and never reach the fake security binary.
func TestStatuslineFailuresAndAlias(t *testing.T) {
	for _, targetPlatform := range []string{"linux", "darwin"} {
		for _, failure := range []string{"none", "empty", "invalid", "null-limits", "missing-limits", "missing-config", "unmanaged", "oversized", "broken-accounts", "broken-usage"} {
			t.Run(targetPlatform+"/"+failure, func(t *testing.T) {
				f := setupSwitchCommand(t, targetPlatform)
				statusClock(t)
				input, want := statusSample, "a\n"
				switch failure {
				case "empty":
					input = ""
				case "invalid":
					input = "invalid JSON"
				case "null-limits":
					input = `{"session_id":"demo","rate_limits":null}`
				case "missing-limits":
					input = `{"session_id":"demo"}`
				case "missing-config":
					if err := os.Remove(f.loc.GlobalConfig); err != nil {
						t.Fatal(err)
					}
					want = ""
				case "unmanaged":
					writeFixture(t, f.loc.GlobalConfig, `{"oauthAccount":{"accountUuid":"unmanaged"}}`)
					want = ""
				case "oversized":
					input = statusSample + strings.Repeat(" ", 1<<20)
				case "broken-accounts":
					writeFixture(t, filepath.Join(f.fast, "state", "accounts.json"), "torn")
					want = ""
				case "broken-usage":
					writeFixture(t, filepath.Join(f.fast, "state", "usage.json"), "torn")
				}
				// Removing the file source also catches an accidental passive credential read.
				if err := os.Remove(f.loc.CredentialsFile); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
				code, out, stderr := hook(t, input, "--json")
				if code != 0 || out != want || stderr != "" {
					t.Fatalf("hook broke display: %d %q %q", code, out, stderr)
				}
				if targetPlatform == "darwin" {
					calls, err := os.ReadFile(filepath.Join(f.keychain, "calls"))
					if err != nil || len(calls) != 0 {
						t.Fatal("hook invoked security")
					}
				}
			})
		}
	}
}

// Invariants 3, 6: hooks record changed samples while accounts and Claude locks remain held elsewhere.
func TestStatuslineRecordsWithoutOtherLocks(t *testing.T) {
	f := setupSwitchCommand(t, "linux")
	statusClock(t)
	lock, err := os.OpenFile(filepath.Join(f.fast, "state", "accounts.lock"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	for _, lock := range claudelock.Locks(f.loc) {
		if err := os.Mkdir(lock.Path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, input := range []string{statusSample, strings.Replace(statusSample, `:42`, `:43`, 1)} {
		if code, out, stderr := hook(t, input); code != 0 || out != "a\n" || stderr != "" {
			t.Fatal("hook waited on unrelated locks")
		}
	}
	state, err := (usageState.Store{Directory: filepath.Join(f.fast, "state")}).Read()
	if err != nil || len(state.Accounts) != 1 {
		t.Fatal("hook did not record changed sample")
	}
	for _, a := range state.Accounts {
		if a.FiveHour.Used != 43 || a.SevenDay.Used != 61.5 || a.Source != "statusline" {
			t.Fatal("hook recorded wrong values")
		}
	}
}

type boundedReader struct{ read int }

func (r *boundedReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	r.read += len(p)
	return len(p), nil
}

func TestStatuslineInputBound(t *testing.T) {
	setupSwitchCommand(t, "linux")
	input := &boundedReader{}
	statusline(input, io.Discard)
	if input.read != (1<<20)+1 {
		t.Fatal("hook exceeded input cap")
	}
}

// Invariant 7: add stores the two public plan strings without any other credential field.
func TestAddPlanMetadata(t *testing.T) {
	home, fast := setupActive(t)
	statusClock(t)
	blob := strings.Replace(activeBlob, `"claudeAiOauth":{`, `"claudeAiOauth":{"subscriptionType":"pro","rateLimitTier":"default_claude_pro","otherToken":"extra-private",`, 1)
	writeFixture(t, filepath.Join(home, ".credentials.json"), blob)
	if code, _, stderr := invoke("add", "--json"); code != 0 || stderr != "" {
		t.Fatal("add with plan failed")
	}
	data, err := os.ReadFile(filepath.Join(fast, "state", "accounts.json"))
	var db struct {
		SchemaVersion int
		Accounts      map[string]map[string]json.RawMessage
	}
	if err != nil || json.Unmarshal(data, &db) != nil || db.SchemaVersion != 1 || len(db.Accounts) != 1 {
		t.Fatal("invalid account metadata")
	}
	for _, a := range db.Accounts {
		if len(a) != 9 || string(a["subscriptionType"]) != `"pro"` || string(a["rateLimitTier"]) != `"default_claude_pro"` {
			t.Fatal("wrong plan metadata or unexpected credential field")
		}
	}
	if strings.Contains(string(data), "private") || strings.Contains(string(data), "Token") || strings.Contains(string(data), "claudeAiOauth") {
		t.Fatal("token substring in accounts.json")
	}
}

// Invariant 8: JSON keeps unknown windows null, sorts active first, and applies idle rollover.
func TestStatusJSON(t *testing.T) {
	f := setupSwitchCommand(t, "darwin")
	statusClock(t)
	writeFixture(t, f.loc.GlobalConfig, secondIdentity)
	state := usageState.State{SchemaVersion: 1, Sessions: map[string]usageState.Session{}, Accounts: map[string]usageState.Account{
		"second-id": {Windows: usageState.Windows{
			FiveHour: &usageState.Window{Used: 99, ResetsAt: statusNow - 1, SeenAt: statusNow - 180},
			SevenDay: &usageState.Window{Used: 80, ResetsAt: statusNow - 2*604800 - 1, SeenAt: statusNow - 180},
		}, Source: "statusline"},
	}}
	data, _ := json.Marshal(state)
	path := filepath.Join(f.fast, "state", "usage.json")
	if err := statehome.AtomicWrite(path, data); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, f.fast)
	code, out, stderr := invoke("status", "--json")
	var result struct {
		Accounts []map[string]json.RawMessage `json:"accounts"`
	}
	if code != 0 || stderr != "" || json.Unmarshal([]byte(out), &result) != nil || len(result.Accounts) != 2 {
		t.Fatalf("status JSON failed: %s", stderr)
	}
	b, a := result.Accounts[0], result.Accounts[1]
	if len(b) != 11 || string(b["models"]) != `{}` || string(b["note"]) != `""` || string(b["alias"]) != `"b"` || string(b["accountUuid"]) != `"second-id"` || string(b["active"]) != `true` ||
		string(b["source"]) != `"statusline"` || string(b["seenAt"]) != "1792069820" || string(b["subscriptionType"]) != `""` || string(b["rateLimitTier"]) != `""` {
		t.Fatal("status account shape or active order differs from contract")
	}
	var five, weekly map[string]any
	json.Unmarshal(b["fiveHour"], &five)
	json.Unmarshal(b["sevenDay"], &weekly)
	if !reflect.DeepEqual(five, map[string]any{"used": float64(0), "resetsAt": float64(0), "known": false}) ||
		!reflect.DeepEqual(weekly, map[string]any{"used": float64(0), "resetsAt": float64(statusNow + 604800 - 1), "known": true, "pace": nil}) {
		t.Fatal("status did not use effective rollover values")
	}
	for _, key := range []string{"fiveHour", "sevenDay", "seenAt", "source"} {
		if string(a[key]) != "null" {
			t.Fatalf("unknown %s must be null", key)
		}
	}
	if string(a["active"]) != "false" || string(a["note"]) != `"access token expired"` || !reflect.DeepEqual(before, snapshot(t, f.fast)) {
		t.Fatal("status changed state")
	}
	calls, err := os.ReadFile(filepath.Join(f.keychain, "calls"))
	if err != nil || string(calls) != "argv find-generic-password fasthands/12345678-1234-1234-1234-123456789abc\n" {
		t.Fatal("status must read only the stale idle account's backup")
	}
}

// Invariant 8: empty stores produce [] without creating state.
func TestStatusEmptyJSON(t *testing.T) {
	home, fast := setupActive(t)
	statusClock(t)
	if err := os.Remove(filepath.Join(home, ".config.json")); err != nil {
		t.Fatal(err)
	}
	if code, out, stderr := invoke("status", "--json"); code != 0 || out != "{\"accounts\":[]}\n" || stderr != "" {
		t.Fatal("empty status must print []")
	}
	if _, err := os.Stat(fast); !os.IsNotExist(err) {
		t.Fatal("empty status created state")
	}
}

func TestStatusHuman(t *testing.T) {
	f := setupSwitchCommand(t, "linux")
	statusClock(t)
	for _, input := range []string{statusSample, strings.Replace(statusSample, `:42`, `:43`, 1)} {
		hook(t, input)
	}
	code, out, stderr := invoke("status")
	if code != 0 || stderr != "" {
		t.Fatal("human status failed")
	}
	fiveReset := time.Unix(1792080000, 0).UTC().Format("15:04")
	weekReset := time.Unix(1792400000, 0).UTC().Format("Mon 15:04")
	if !strings.HasPrefix(out, "a\t*\t43%\t"+fiveReset+"\t61.5%\t"+weekReset+"\t+16.1\t0s ago\t-\t\n") ||
		!strings.HasSuffix(out, "b\t\t-\t-\t-\t-\t-\tnever\t-\taccess token expired\n") {
		t.Fatalf("wrong human status: %q", out)
	}
	if _, err := os.Stat(filepath.Join(f.fast, "state", "usage.lock")); err != nil {
		t.Fatal(err)
	}
}

func TestStatusUsageAndErrors(t *testing.T) {
	f := setupSwitchCommand(t, "linux")
	for _, args := range [][]string{{"status", "extra"}, {"status", "--json=bad"}} {
		if code, _, stderr := invoke(args...); code != 2 || stderr == "" {
			t.Fatal("invalid status arguments accepted")
		}
	}
	if code, out, stderr := invoke("status", "--help"); code != 0 || !strings.Contains(out, "hook statusline") || stderr != "" {
		t.Fatal("status or hook missing from usage")
	}
	writeFixture(t, filepath.Join(f.fast, "state", "usage.json"), "torn")
	if code, out, stderr := invoke("status", "--json"); code != 1 || out != "" || !strings.Contains(stderr, "invalid usage") {
		t.Fatal("status swallowed usage error")
	}
}

func BenchmarkStatusline(b *testing.B) {
	// The unit tests own setup isolation; benchmark an existing temporary managed login.
	root := b.TempDir()
	for key, value := range map[string]string{
		"HOME": root, "USER": "test-user", "CLAUDE_CONFIG_DIR": root,
		"CLAUDE_SECURESTORAGE_CONFIG_DIR": root, "FASTHANDS_HOME": root, "TZ": "UTC",
	} {
		b.Setenv(key, value)
	}
	if err := os.WriteFile(filepath.Join(root, ".config.json"), []byte(activeIdentity), 0600); err != nil {
		b.Fatal(err)
	}
	if err := statehome.AtomicWrite(filepath.Join(root, "state", "accounts.json"), []byte(`{"schemaVersion":1,"accounts":{"12345678-1234-1234-1234-123456789abc":{"alias":"a"}}}`)); err != nil {
		b.Fatal(err)
	}
	oldNow := now
	now = func() time.Time { return time.Unix(statusNow, 0) }
	b.Cleanup(func() { now = oldNow })
	statusline(strings.NewReader(statusSample), io.Discard)
	b.ResetTimer()
	for b.Loop() {
		statusline(bytes.NewBufferString(statusSample), io.Discard)
	}
}

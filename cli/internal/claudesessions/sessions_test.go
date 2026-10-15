package claudesessions

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func sessionHome(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for key, value := range map[string]string{
		"HOME": root, "USER": "test-user", "CLAUDE_CONFIG_DIR": root,
		"CLAUDE_SECURESTORAGE_CONFIG_DIR": root, "FASTHANDS_HOME": filepath.Join(root, "fasthands"),
	} {
		t.Setenv(key, value)
	}
	if err := os.Mkdir(filepath.Join(root, "sessions"), 0700); err != nil {
		t.Fatal(err)
	}
	old := processProbe
	t.Cleanup(func() { processProbe = old })
	return root
}

func writeRecord(t *testing.T, home, name, data string) string {
	t.Helper()
	path := filepath.Join(home, "sessions", name)
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Invariant 1: ignored files never reach record parsing or the process probe.
func TestScanIgnoresKeysAndNonDigitNames(t *testing.T) {
	home := sessionHome(t)
	for _, name := range []string{"42.abcd.key", "notes.json", ".json", "42.json.key", "-42.json", "4x.json"} {
		path := writeRecord(t, home, name, "invalid JSON")
		if err := os.Chmod(path, 0000); err != nil {
			t.Fatal(err)
		}
	}
	processProbe.alive = func(int) bool { t.Fatal("ignored file reached probe"); return false }
	sessions, err := Scan(home)
	if err != nil || len(sessions) != 0 {
		t.Fatal("key or non-digit name was read")
	}
}

// Invariant 2: both procStart formats run under the same injected probe on every OS.
func TestScanLiveness(t *testing.T) {
	for _, tt := range []struct {
		name, recorded, live string
		pid                  int
		alive, unknown, want bool
	}{
		{"dead", "100", "100", 42, false, false, false},
		{"ticks-match", "100", "100", 42, true, false, true},
		{"ticks-recycled", "100", "101", 42, true, false, false},
		{"ticks-unreadable", "100", "", 42, true, true, true},
		{"ticks-unparseable", "100", "bad", 42, true, false, true},
		{"lstart-match", "Thu Oct 15 09:58:12 2026", "Thu Oct 15 09:58:12 2026", 42, true, false, true},
		{"lstart-recycled", "Thu Oct 15 09:58:12 2026", "Thu Oct 15 10:00:13 2026", 42, true, false, false},
		{"lstart-slack", "Thu Oct 15 09:58:12 2026", "Thu Oct 15 10:00:12 2026", 42, true, false, true},
		{"lstart-earlier", "Thu Oct 15 09:58:12 2026", "Thu Oct 15 09:50:12 2026", 42, true, false, true},
		{"lstart-unreadable", "Thu Oct 15 09:58:12 2026", "", 42, true, true, true},
		{"lstart-unparseable", "Thu Oct 15 09:58:12 2026", "bad", 42, true, false, true},
		{"missing-start", "", "Thu Oct 15 10:00:13 2026", 42, true, false, true},
		{"bad-start", "bad", "Thu Oct 15 10:00:13 2026", 42, true, false, true},
		{"pid-one", "100", "100", 1, true, false, false},
		{"pid-zero", "100", "100", 0, true, false, false},
		{"pid-negative", "100", "100", -1, true, false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			home := sessionHome(t)
			processProbe.alive = func(pid int) bool {
				if pid != tt.pid || pid <= 1 {
					t.Fatal("invalid pid reached probe")
				}
				return tt.alive
			}
			processProbe.start = func(pid int, ticks bool) (string, error) {
				if pid != tt.pid || ticks != digits(tt.recorded) {
					t.Fatal("start format or pid changed")
				}
				if tt.unknown {
					return "", errors.New("unreadable start")
				}
				return tt.live, nil
			}
			blob, _ := json.Marshal(map[string]any{"pid": tt.pid, "procStart": tt.recorded, "status": "busy", "cwd": "/work", "kind": "interactive"})
			path := writeRecord(t, home, "42.json", string(blob))
			sessions, err := Scan(home)
			if err != nil || (len(sessions) == 1) != tt.want {
				t.Fatalf("wrong liveness: %v, %v", sessions, err)
			}
			if tt.want && sessions[0] != (Session{PID: tt.pid, Status: "busy", CWD: "/work", Kind: "interactive", Path: path}) {
				t.Fatal("session fields changed")
			}
		})
	}
}

// Invariants 3, 4: Linux comm and macOS space-padded days need delimiter-based parsing.
func TestProcessStartParsing(t *testing.T) {
	stat := "42 (worker ) with spaces)) S " + strings.Repeat("0 ", 18) + "12345 99"
	if got, err := parseStat(stat); err != nil || got != "12345" {
		t.Fatalf("wrong starttime field: %q, %v", got, err)
	}
	for _, stat := range []string{"no parentheses", "42 (worker) S 0", "42 (worker) S " + strings.Repeat("0 ", 18) + "bad"} {
		if _, err := parseStat(stat); err == nil {
			t.Fatal("invalid stat accepted")
		}
	}
	got, err := parseStart("  Fri Jan  2 15:04:05 2026\n")
	if err != nil || !got.Equal(time.Date(2026, time.January, 2, 15, 4, 5, 0, time.UTC)) || got.Location() != time.UTC {
		t.Fatal("space-padded lstart did not parse in UTC")
	}
}

// Invariant 5: missing and future states block switching, including records read by Scan.
func TestMidTurnStatuses(t *testing.T) {
	home := sessionHome(t)
	processProbe.alive = func(int) bool { return true }
	processProbe.start = func(int, bool) (string, error) { return "100", nil }
	for _, status := range []string{"busy", "", "waiting", "idle", "shell"} {
		record := `{"pid":42,"procStart":"100"}`
		if status != "" {
			record = strings.TrimSuffix(record, "}") + `,"status":"` + status + `"}`
		}
		writeRecord(t, home, "42.json", record)
		sessions, err := Scan(home)
		want := status != "idle" && status != "shell"
		if err != nil || len(sessions) != 1 || (len(MidTurn(sessions)) == 1) != want {
			t.Fatalf("wrong mid-turn classification for %q", status)
		}
	}
}

// Invariant 6: parse and read failures remain mid-turn and identify the record path.
func TestUnreadableRecords(t *testing.T) {
	home := sessionHome(t)
	processProbe.alive = func(int) bool { t.Fatal("unreadable record reached probe"); return false }
	for _, data := range []string{"not JSON", "null", `{"pid":"bad"}`} {
		path := writeRecord(t, home, "42.json", data)
		sessions, err := Scan(home)
		want := []Session{{Path: path, Unreadable: true}}
		if err != nil || !reflect.DeepEqual(sessions, want) || !reflect.DeepEqual(MidTurn(sessions), want) {
			t.Fatal("unreadable record was lost")
		}
	}
	path := filepath.Join(home, "sessions", "43.json")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	sessions, err := Scan(home)
	if err != nil || len(MidTurn(sessions)) != 2 || sessions[1].Path != path || !sessions[1].Unreadable {
		t.Fatal("record read failure was lost")
	}
	if len(MidTurn([]Session{{Status: "idle", Unreadable: true}})) != 1 {
		t.Fatal("unreadable must override safe status")
	}
}

func TestSessionsDirectory(t *testing.T) {
	home := sessionHome(t)
	dir := filepath.Join(home, "sessions")
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if sessions, err := Scan(home); err != nil || len(sessions) != 0 {
		t.Fatal("missing directory must be empty")
	}
	if err := os.WriteFile(dir, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(home); err == nil || !strings.Contains(err.Error(), dir) {
		t.Fatal("unreadable directory must fail with its path")
	}
}

// Invariant 11: only this test uses the real OS process probe.
func TestRealProcessProbe(t *testing.T) {
	sessionHome(t)
	pid := os.Getpid()
	if !processProbe.alive(pid) || processProbe.alive(1) || processProbe.alive(0) || processProbe.alive(-1) {
		t.Fatal("wrong real process liveness")
	}
	ticks := runtime.GOOS == "linux"
	start, err := processProbe.start(pid, ticks)
	if err != nil || start == "" {
		t.Fatalf("cannot read own process start: %v", err)
	}
	if ticks {
		if !digits(start) {
			t.Fatal("Linux start must be ticks")
		}
	} else if _, err := parseStart(start); err != nil {
		t.Fatalf("macOS start must be lstart: %v", err)
	}
}

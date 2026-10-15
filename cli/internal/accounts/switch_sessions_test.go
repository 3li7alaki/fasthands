package accounts

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"fasthands/internal/claudelock"
	"fasthands/internal/claudesessions"
	"fasthands/internal/statehome"
)

func setupSession(t *testing.T, f *switchFixture) (string, func(string) []byte) {
	t.Helper()
	dir := filepath.Join(f.loc.ConfigHome, "sessions")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "42.json")
	record := func(status string) []byte {
		data, _ := json.Marshal(claudesessions.Session{PID: 42, Status: status, CWD: "/work/project", Kind: "interactive"})
		return data
	}
	put(t, path, record("busy"))
	oldScan, oldPoll := switchScan, switchPollInterval
	switchPollInterval = 10 * time.Millisecond
	// The scanner tests own process liveness; switch tests inject a known live record.
	switchScan = func(home string) ([]claudesessions.Session, error) {
		if home != f.loc.ConfigHome || home == f.loc.StorageDir {
			t.Fatal("switch must scan config home, not secure storage")
		}
		data, err := os.ReadFile(path)
		var session claudesessions.Session
		if err != nil || json.Unmarshal(data, &session) != nil {
			return []claudesessions.Session{{Path: path, Unreadable: true}}, nil
		}
		session.Path = path
		return []claudesessions.Session{session}, nil
	}
	t.Cleanup(func() { switchScan, switchPollInterval = oldScan, oldPoll })
	return path, record
}

func assertSessionLocks(t *testing.T, f *switchFixture, held bool) {
	t.Helper()
	for _, lock := range claudelock.Locks(f.loc) {
		_, err := os.Stat(lock.Path)
		if held && err != nil || !held && !errors.Is(err, os.ErrNotExist) {
			t.Fatal("wrong Claude lock state during session scan")
		}
	}
	file, err := os.OpenFile(filepath.Join(f.m.Paths.State, "accounts.lock"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	}
	if held && !errors.Is(err, syscall.EWOULDBLOCK) || !held && err != nil {
		t.Fatal("wrong accounts flock state during session scan")
	}
}

// Invariant 7: no-wait refusal preserves live login, config, metadata, and both backup generations.
func TestSwitchMidTurnRefusesWithoutWrites(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			f := setupSwitch(t, platform)
			setupSession(t, f)
			if err := f.m.Store.WritePrev("id-a", []byte(oldLogin)); err != nil {
				t.Fatal(err)
			}
			before := f.snapshot(t)
			beforeSwitchWrite = func(string) { t.Fatal("mid-turn refusal attempted a write") }
			_, err := f.m.Switch("b", f.loc, platform, f.security, SwitchOptions{})
			want := "1 Claude session(s) mid-turn: pid 42 (cwd /work/project); retry when they finish, or pass --wait or --force"
			if err == nil || err.Error() != want || !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatalf("mid-turn refusal changed state or message: %v", err)
			}
			assertSessionLocks(t, f, false)
		})
	}
}

// Invariant 8: busy-to-idle polling holds no locks and lands after the record changes.
func TestSwitchWaitsForIdle(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			f := setupSwitch(t, platform)
			path, record := setupSession(t, f)
			scan := switchScan
			unlocked, locked, busy := 0, 0, false
			switchScan = func(home string) ([]claudesessions.Session, error) {
				_, err := os.Stat(claudelock.Locks(f.loc)[0].Path)
				held := err == nil
				assertSessionLocks(t, f, held)
				if held {
					locked++
				} else {
					unlocked++
				}
				sessions, err := scan(home)
				busy = busy || len(claudesessions.MidTurn(sessions)) != 0
				return sessions, err
			}
			done := make(chan error, 1)
			idle := record("idle")
			go func() {
				time.Sleep(25 * time.Millisecond)
				done <- statehome.ReplaceFile(path, idle)
			}()
			result, err := f.m.Switch("b", f.loc, platform, f.security, SwitchOptions{Wait: time.Second})
			if writeErr := <-done; writeErr != nil {
				t.Fatal(writeErr)
			}
			if err != nil || !result.Switched || !busy || unlocked < 2 || locked != 1 {
				t.Fatalf("switch did not wait without locks: %v", err)
			}
			assertSessionLocks(t, f, false)
		})
	}
}

// Invariant 9: force skips polling, still scans under all locks, and reports every mid-turn session.
func TestSwitchForceWarns(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			f := setupSwitch(t, platform)
			path, _ := setupSession(t, f)
			scan := switchScan
			calls := 0
			switchScan = func(home string) ([]claudesessions.Session, error) {
				assertSessionLocks(t, f, true)
				calls++
				sessions, err := scan(home)
				return append(sessions, claudesessions.Session{Path: path + ".unreadable", Unreadable: true}), err
			}
			result, err := f.m.Switch("b", f.loc, platform, f.security, SwitchOptions{Wait: time.Hour, Force: true})
			want := "2 Claude session(s) mid-turn: pid 42 (cwd /work/project), unreadable record " + path + ".unreadable"
			if err != nil || !result.Switched || calls != 1 || !reflect.DeepEqual(result.Warnings, []string{want}) {
				t.Fatalf("forced switch lost warning or waited: %v", err)
			}
			assertSessionLocks(t, f, false)
		})
	}
}

// The Claude session running fasthands (CLAUDE_PID) is busy by definition and never blocks its own switch.
func TestSwitchIgnoresCallingSession(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			f := setupSwitch(t, platform)
			setupSession(t, f)
			t.Setenv("CLAUDE_PID", "42")
			result, err := f.m.Switch("b", f.loc, platform, f.security, SwitchOptions{})
			if err != nil || !result.Switched || len(result.Warnings) != 0 {
				t.Fatalf("calling session blocked or warned its own switch: %v", err)
			}
			t.Setenv("CLAUDE_PID", "43")
			if _, err := f.m.Switch("a", f.loc, platform, f.security, SwitchOptions{}); err == nil || !strings.Contains(err.Error(), "pid 42") {
				t.Fatalf("another session's turn did not block the switch: %v", err)
			}
		})
	}
}

// Invariant 10: the unlocked identity hint avoids waiting, while the locked check stays authoritative.
func TestSwitchAlreadyActiveMidTurn(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			f := setupSwitch(t, platform)
			setupSession(t, f)
			switchPollInterval = time.Second
			switchScan = func(string) ([]claudesessions.Session, error) {
				t.Fatal("already-active switch scanned sessions")
				return nil, nil
			}
			before := f.snapshot(t)
			start := time.Now()
			result, err := f.m.Switch("a", f.loc, platform, f.security, SwitchOptions{Wait: time.Minute})
			if time.Since(start) >= switchPollInterval/2 || err != nil || result.Switched || !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatalf("already-active switch waited or changed state: %v", err)
			}
		})
	}
}

func TestSwitchRechecksSessionsUnderLocks(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			f := setupSwitch(t, platform)
			path, _ := setupSession(t, f)
			calls := 0
			switchScan = func(string) ([]claudesessions.Session, error) {
				calls++
				assertSessionLocks(t, f, calls == 2)
				if calls == 1 {
					return nil, nil
				}
				return []claudesessions.Session{{Path: path, Unreadable: true}}, nil
			}
			before := f.snapshot(t)
			_, err := f.m.Switch("b", f.loc, platform, f.security, SwitchOptions{Wait: time.Second})
			if err == nil || !strings.Contains(err.Error(), "unreadable record "+path) || calls != 2 || !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatal("locked scan did not catch the newly busy session")
			}
			assertSessionLocks(t, f, false)
		})
	}
}

func TestSwitchWaitDeadlineAndScanErrors(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		for _, failure := range []string{"timeout", "unlocked-error", "locked-error"} {
			t.Run(platform+"/"+failure, func(t *testing.T) {
				f := setupSwitch(t, platform)
				setupSession(t, f)
				switchPollInterval = time.Second
				scan, calls := switchScan, 0
				switchScan = func(home string) ([]claudesessions.Session, error) {
					calls++
					if failure == "unlocked-error" || failure == "locked-error" && calls == 2 {
						return nil, errors.New("cannot scan sessions")
					}
					if failure == "locked-error" {
						return nil, nil
					}
					return scan(home)
				}
				before := f.snapshot(t)
				start := time.Now()
				_, err := f.m.Switch("b", f.loc, platform, f.security, SwitchOptions{Wait: 20 * time.Millisecond})
				elapsed := time.Since(start)
				if err == nil || !reflect.DeepEqual(before, f.snapshot(t)) || elapsed > 500*time.Millisecond {
					t.Fatalf("wait or scan failure changed state or exceeded deadline: %v", err)
				}
				if failure == "timeout" && (elapsed < 20*time.Millisecond || calls < 3) {
					t.Fatal("wait did not poll until its deadline")
				}
				assertSessionLocks(t, f, false)
			})
		}
	}
}

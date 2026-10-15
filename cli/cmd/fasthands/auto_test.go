package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"fasthands/internal/accounts"
	"fasthands/internal/claudecfg"
	"fasthands/internal/credstore"
	"fasthands/internal/picker"
	"fasthands/internal/statehome"
	usageState "fasthands/internal/usage"
)

func TestMain(m *testing.M) {
	if os.Getenv("FH_DETACHED_CHILD") == "1" {
		time.Sleep(time.Second)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func setupAutoHook(t *testing.T, targetPlatform string) (commandSwitchFixture, *int) {
	t.Helper()
	f := setupSwitchCommand(t, targetPlatform)
	statusClock(t)
	pickerUsage(t, f, 92)
	calls, old := new(int), spawnAuto
	spawnAuto = func() error {
		*calls++
		if _, err := os.Stat(filepath.Join(f.fast, "state", "auto.spawned")); err != nil {
			t.Error("spawn preceded debounce stamp")
		}
		lock, err := autoLock(filepath.Join(f.fast, "state"))
		if err != nil || lock == nil {
			t.Error("hook held auto.lock while spawning its child")
		} else {
			lock.Close()
		}
		return nil
	}
	t.Cleanup(func() { spawnAuto = old })
	usageServer(t, func(w http.ResponseWriter, r *http.Request) { t.Error("hook reached an endpoint") })
	return f, calls
}

// Slice 5b invariant 1: switching spawns once; cooldown holds leave no debounce marker.
func TestStatuslineAutoDecision(t *testing.T) {
	for _, targetPlatform := range []string{"linux", "darwin"} {
		for _, hold := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/hold=%t", targetPlatform, hold), func(t *testing.T) {
				f, calls := setupAutoHook(t, targetPlatform)
				if hold {
					if err := (usageState.Store{Directory: filepath.Join(f.fast, "state")}).MarkSwitch(statusNow); err != nil {
						t.Fatal(err)
					}
				}
				if code, out, stderr := hook(t, statusSample); code != 0 || out != "a\n" || stderr != "" {
					t.Fatal("trigger changed hook output")
				}
				info, err := os.Stat(filepath.Join(f.fast, "state", "auto.spawned"))
				if hold {
					if *calls != 0 || !os.IsNotExist(err) {
						t.Fatal("held decision spawned or stamped")
					}
				} else if *calls != 1 || err != nil || info.Mode().Perm() != 0600 || info.ModTime().Unix() != statusNow {
					t.Fatal("switch did not spawn once with a private stamp")
				}
				if targetPlatform == "darwin" {
					data, err := os.ReadFile(filepath.Join(f.keychain, "calls"))
					if err != nil || len(data) != 0 {
						t.Fatal("hook read credentials")
					}
				}
			})
		}
	}
}

// Slice 5b invariant 1: the sample can lift cooldown only after recording and re-reading usage.
func TestStatuslineAutoUsesRecordedUsage(t *testing.T) {
	f, calls := setupAutoHook(t, "linux")
	if err := (usageState.Store{Directory: filepath.Join(f.fast, "state")}).MarkSwitch(statusNow); err != nil {
		t.Fatal(err)
	}
	input := fmt.Sprintf(`{"session_id":"fresh","rate_limits":{"seven_day":{"used_percentage":100,"resets_at":%d}}}`, statusNow+20000)
	if code, out, stderr := hook(t, input); code != 0 || out != "a\n" || stderr != "" || *calls != 1 {
		t.Fatal("hook decided before recording the at-limit sample")
	}
}

// Slice 5b invariant 2: debounce includes second 59 and expires at exactly 60 seconds.
func TestStatuslineAutoDebounce(t *testing.T) {
	f, calls := setupAutoHook(t, "linux")
	path := filepath.Join(f.fast, "state", "auto.spawned")
	hook(t, statusSample)
	clock := time.Unix(statusNow+59, 0)
	now = func() time.Time { return clock }
	hook(t, statusSample)
	if *calls != 1 {
		t.Fatal("second session bypassed debounce")
	}
	old := clock.Add(-time.Minute)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	hook(t, statusSample)
	if *calls != 2 {
		t.Fatal("minute-old stamp suppressed a switch")
	}
	info, err := os.Stat(path)
	if err != nil || !info.ModTime().Equal(clock) {
		t.Fatal("debounce stamp did not refresh")
	}
}

// Slice 5b invariant 2: concurrent sessions share one check-and-stamp operation.
func TestStatuslineAutoDebounceConcurrent(t *testing.T) {
	_, _ = setupAutoHook(t, "linux")
	paths, err := statehome.Locate()
	if err != nil {
		t.Fatal(err)
	}
	list, err := (accounts.Manager{Paths: paths}).Pickable(usageState.State{})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	spawnAuto = func() error { calls.Add(1); return nil }
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() { triggerAuto(paths.State, append([]picker.Account(nil), list...), activeID) })
	}
	workers.Wait()
	if calls.Load() != 1 {
		t.Fatal("concurrent sessions bypassed the shared debounce")
	}
}

// Slice 5b invariant 3: only the hook respects off; an explicit --once still switches.
func TestAutoDisabledHookAndExplicitOnce(t *testing.T) {
	f, calls := setupAutoHook(t, "linux")
	if code, _, stderr := invoke("auto", "off"); code != 0 || stderr != "" {
		t.Fatal("cannot disable auto")
	}
	hook(t, statusSample)
	if *calls != 0 {
		t.Fatal("disabled hook spawned")
	}
	if code, _, stderr := invoke("auto", "on"); code != 0 || stderr != "" {
		t.Fatal("cannot enable auto")
	}
	hook(t, statusSample)
	if *calls != 1 {
		t.Fatal("enabled hook did not spawn")
	}
	invoke("auto", "off")
	store := credstore.New(platform, securityPath, filepath.Join(f.fast, "credentials"))
	if err := store.Write("second-id", []byte(validUsageLogin(secondBlob))); err != nil {
		t.Fatal(err)
	}
	requests := 0
	usageServer(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		fmt.Fprintf(w, `{"seven_day":{"utilization":20,"resets_at":%q}}`, time.Unix(statusNow+10000, 0).UTC().Format(time.RFC3339))
	})
	if code, out, stderr := invoke("auto", "--once", "--json"); code != 0 || stderr != "" || !strings.Contains(out, `"switched":true`) {
		t.Fatalf("explicit auto ignored off incorrectly: %d %q %q", code, out, stderr)
	}
	if live, err := claudecfg.ActiveUUID(f.loc); err != nil || live != "second-id" || requests != 1 {
		t.Fatal("disabled explicit auto did not refresh and switch")
	}
	if _, err := os.Stat(filepath.Join(f.fast, "state", "auto.disabled")); err != nil {
		t.Fatal("explicit auto changed the disabled flag")
	}
}

// Slice 5b invariant 4: spawn, debounce-write, and usage failures preserve the display contract.
func TestStatuslineAutoFailures(t *testing.T) {
	for _, failure := range []string{"spawn", "stamp", "usage"} {
		t.Run(failure, func(t *testing.T) {
			f, calls := setupAutoHook(t, "linux")
			switch failure {
			case "spawn":
				original := spawnAuto
				spawnAuto = func() error { original(); return errors.New("injected spawn failure") }
			case "stamp":
				// A directory blocks atomic replacement even when tests run as root.
				path := filepath.Join(f.fast, "state", "auto.spawned")
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				old := now().Add(-time.Minute)
				if err := os.Chtimes(path, old, old); err != nil {
					t.Fatal(err)
				}
			case "usage":
				writeFixture(t, filepath.Join(f.fast, "state", "usage.json"), "torn")
			}
			for range 2 {
				if code, out, stderr := hook(t, statusSample, "--json"); code != 0 || out != "a\n" || stderr != "" {
					t.Fatalf("trigger failure broke display: %d %q %q", code, out, stderr)
				}
			}
			want := 0
			if failure == "spawn" {
				want = 1
			}
			if *calls != want {
				t.Fatal("failed trigger bypassed debounce or spawned without a stamp")
			}
		})
	}
}

// Slice 5b invariant 5: exercise the production helper with a real, released session leader.
func TestDetachedAutoProcess(t *testing.T) {
	setupActive(t)
	statusClock(t)
	t.Setenv("CLAUDE_SECURESTORAGE_CONFIG_DIR", os.Getenv("CLAUDE_CONFIG_DIR"))
	t.Setenv("FH_DETACHED_CHILD", "1")
	pid, err := startDetached(os.Args[0], "-test.run=^$")
	if err != nil {
		t.Fatalf("cannot start detached child: %v", err)
	}
	defer syscall.Kill(pid, syscall.SIGKILL)
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		// Go exposes Getsid on macOS but not Linux; the syscall exists on both.
		sid, _, errno := syscall.Syscall(syscall.SYS_GETSID, uintptr(pid), 0, 0)
		if errno == 0 && sid == uintptr(pid) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("child is not a session leader: pid=%d sid=%d err=%v", pid, sid, errno)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatalf("cannot kill detached child: %v", err)
	}
	// A released child can remain a zombie; never poll kill(pid, 0) for exit.
}

// Slice 5b invariant 6: use only the final complete log line, with a fixed read ceiling.
func TestStatusLastAutoSwitch(t *testing.T) {
	for _, mode := range []string{"absent", "empty", "multi", "large", "no-newline", "malformed", "bad-time", "oversized", "blank-last"} {
		t.Run(mode, func(t *testing.T) {
			_, fast := setupActive(t)
			statusClock(t)
			path := filepath.Join(fast, "state", "auto.log")
			valid := time.Unix(statusNow, 0).UTC().Format(time.RFC3339) + "\ta\tb\trule 3: b eligible\n"
			data, want := "earlier malformed line\n"+valid, true
			switch mode {
			case "absent", "empty":
				data, want = "", false
			case "large":
				data = strings.Repeat("old line\n", 1024) + valid
			case "no-newline":
				data = strings.TrimSuffix(valid, "\n")
			case "malformed":
				data, want = valid+"torn\n", false
			case "bad-time":
				data, want = valid+"invalid\ta\tb\treason\n", false
			case "oversized":
				data, want = valid+strings.TrimSuffix(valid, "\n")+strings.Repeat("x", 4096)+"\n", false
			case "blank-last":
				data, want = valid+"\n", false
			}
			if mode != "absent" {
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				writeFixture(t, path, data)
			}
			code, out, stderr := invoke("status")
			footer := "last auto switch: " + time.Unix(statusNow, 0).Local().Format("Mon 15:04") + " a -> b (rule 3: b eligible)\n"
			if code != 0 || stderr != "" || want && out != footer || !want && out != "" {
				t.Fatalf("wrong auto footer: %d %q %q", code, out, stderr)
			}
			code, out, stderr = invoke("status", "--json")
			var result struct {
				Accounts       []statusAccount
				LastAutoSwitch *autoSwitch
			}
			var shape map[string]json.RawMessage
			if code != 0 || stderr != "" || json.Unmarshal([]byte(out), &result) != nil || json.Unmarshal([]byte(out), &shape) != nil || len(shape) != 2 || result.Accounts == nil || (result.LastAutoSwitch != nil) != want {
				t.Fatal("wrong status log JSON shape")
			}
			if want {
				var entry map[string]json.RawMessage
				if json.Unmarshal(shape["lastAutoSwitch"], &entry) != nil || len(entry) != 4 || *result.LastAutoSwitch != (autoSwitch{statusNow, "a", "b", "rule 3: b eligible"}) {
					t.Fatal("wrong last switch fields")
				}
			} else if string(shape["lastAutoSwitch"]) != "null" {
				t.Fatal("absent or malformed log must produce null")
			}
		})
	}
}

type boundedAutoLog struct {
	tail       string
	size, read int64
}

func (log *boundedAutoLog) ReadAt(p []byte, offset int64) (int, error) {
	if offset < log.size-int64(len(log.tail)) || log.read+int64(len(p)) > 4096 {
		return 0, errors.New("read exceeded auto log tail")
	}
	n, err := strings.NewReader(log.tail).ReadAt(p, offset-(log.size-int64(len(log.tail))))
	log.read += int64(n)
	return n, err
}

// Slice 5b invariant 6: a virtual 1 GiB log permits no reads outside its final 4 KiB.
func TestAutoLogReadBound(t *testing.T) {
	valid := time.Unix(statusNow, 0).UTC().Format(time.RFC3339) + "\ta\tb\treason\n"
	log := &boundedAutoLog{tail: strings.Repeat("x", 4096-len(valid)-1) + "\n" + valid, size: 1 << 30}
	last := readLastAutoSwitch(log, log.size)
	if last == nil || *last != (autoSwitch{statusNow, "a", "b", "reason"}) || log.read > 4096 {
		t.Fatal("tail lookup exceeded its read bound or lost the final line")
	}
}

// Slice 5b invariant 7: flag writes are private and idempotent; reads and on create no state.
func TestAutoStateAndPick(t *testing.T) {
	_, fast := setupActive(t)
	statusClock(t)
	for _, args := range [][]string{{"auto"}, {"auto", "on"}, {"auto", "on"}, {"auto", "--once=false"}} {
		if code, out, stderr := invoke(args...); code != 0 || out != "auto switching on\n" || stderr != "" {
			t.Fatal("auto on is not idempotent")
		}
	}
	if _, err := os.Stat(fast); !os.IsNotExist(err) {
		t.Fatal("reading auto state or enabling created state")
	}
	f := setupSwitchCommand(t, "linux")
	pickerUsage(t, f, 92)
	for _, action := range []string{"off", "off", "on", "on"} {
		if code, out, stderr := invoke("auto", action); code != 0 || out != "auto switching "+action+"\n" || stderr != "" {
			t.Fatal("wrong auto human output")
		}
		enabled := action == "on"
		path := filepath.Join(f.fast, "state", "auto.disabled")
		info, err := os.Stat(path)
		if !enabled {
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("disabled flag is not private")
			}
			if err := os.Chmod(path, 0644); err != nil {
				t.Fatal(err)
			}
		} else if !os.IsNotExist(err) {
			t.Fatal("on left disabled flag")
		}
		for _, args := range [][]string{{"auto", action, "--json"}, {"auto", "--json", action}, {"auto", "--json"}} {
			if code, out, stderr := invoke(args...); code != 0 || out != fmt.Sprintf("{\"auto\":%t}\n", enabled) || stderr != "" {
				t.Fatal("wrong auto JSON shape")
			}
		}
		if !enabled {
			info, err = os.Stat(path)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("repeated off did not tighten permissions")
			}
		}
		if code, out, stderr := invoke("pick"); code != 0 || stderr != "" || strings.HasSuffix(out, "auto switching off\n") == enabled {
			t.Fatal("pick did not report disabled auto")
		}
		code, out, stderr := invoke("pick", "--json")
		var shape map[string]json.RawMessage
		if code != 0 || stderr != "" || json.Unmarshal([]byte(out), &shape) != nil || len(shape) != 5 || string(shape["auto"]) != fmt.Sprint(enabled) || shape["switched"] != nil {
			t.Fatal("wrong pick auto state JSON")
		}
	}
}

// Slice 5b invariant 1: hook and pick share weights, priority, models, and cooldown.
func TestStatuslineAutoPickerInputs(t *testing.T) {
	for _, tt := range []struct {
		tier            string
		rank            int
		model, cooldown bool
		want            string
	}{
		{"unknown", 0, false, false, "hold"}, {"default_claude_max_5x", 0, false, false, "hold"},
		{"default_claude_max_20x", 0, false, false, "switch"}, {"unknown", 1, false, false, "switch"},
		{"default_claude_max_20x", 0, true, false, "hold"}, {"default_claude_max_20x", 0, false, true, "hold"},
	} {
		_, calls := setupAutoHook(t, "linux")
		paths, err := statehome.Locate()
		if err != nil {
			t.Fatal(err)
		}
		m := accounts.Manager{Paths: paths}
		metadata, err := m.Read()
		if err != nil {
			t.Fatal(err)
		}
		state, err := (usageState.Store{Directory: m.Paths.State}).Read()
		if err != nil {
			t.Fatal(err)
		}
		metadata["third-id"] = accounts.Account{Alias: "c", RateLimitTier: tt.tier, Priority: tt.rank}
		a := metadata["second-id"]
		a.RateLimitTier = "default_claude_max_5x"
		metadata["second-id"] = a
		state.Accounts[activeID].SevenDay.Used = 40
		state.Accounts[activeID].SevenDay.ResetsAt = statusNow + 13000
		state.Accounts["third-id"] = usageState.Account{Windows: usageState.Windows{SevenDay: &usageState.Window{Used: 60, ResetsAt: statusNow + 9000}}}
		if tt.model {
			c := state.Accounts["third-id"]
			c.Models = map[string]*usageState.Window{"Fable": {Used: 95, ResetsAt: statusNow + 9000}}
			state.Accounts["third-id"] = c
		}
		if tt.cooldown {
			state.LastSwitchAt = statusNow
		}
		data, err := json.Marshal(struct {
			SchemaVersion int                         `json:"schemaVersion"`
			Accounts      map[string]accounts.Account `json:"accounts"`
		}{1, metadata})
		if err != nil {
			t.Fatal(err)
		}
		writeFixture(t, filepath.Join(m.Paths.State, "accounts.json"), string(data))
		data, err = json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		writeFixture(t, filepath.Join(m.Paths.State, "usage.json"), string(data))
		code, out, stderr := invoke("pick", "--json")
		var d picker.Decision
		if code != 0 || stderr != "" || json.Unmarshal([]byte(out), &d) != nil || d.Action != tt.want {
			t.Fatal("invalid picker input fixture")
		}
		if code, out, stderr := hook(t, statusSample); code != 0 || out != "a\n" || stderr != "" || (*calls == 1) != (tt.want == "switch") {
			t.Fatal("hook weights, priority, models, or cooldown differ from pick")
		}
	}
}

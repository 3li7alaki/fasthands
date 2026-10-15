package usage

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"fasthands/internal/statehome"
)

const timestamp int64 = 1792070000

func store(t *testing.T) Store {
	t.Helper()
	root := t.TempDir()
	for key, value := range map[string]string{
		"HOME": root, "USER": "test-user", "CLAUDE_CONFIG_DIR": root,
		"CLAUDE_SECURESTORAGE_CONFIG_DIR": root, "FASTHANDS_HOME": root, "TZ": "UTC",
	} {
		t.Setenv(key, value)
	}
	return Store{Directory: filepath.Join(root, "state")}
}

func read(t *testing.T, s Store) State {
	t.Helper()
	state, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func save(t *testing.T, s Store, state State) {
	t.Helper()
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := statehome.AtomicWrite(filepath.Join(s.Directory, "usage.json"), data); err != nil {
		t.Fatal(err)
	}
}

func sample(used float64, reset int64) Sample {
	return Sample{SessionID: "session", RateLimits: &Limits{FiveHour: &Reading{used, timestamp + 1000}, SevenDay: &Reading{used, reset}}}
}

// Invariant 1: reset math is pure and keeps unknown resets and missing windows distinct.
func TestEffective(t *testing.T) {
	for _, tt := range []struct {
		name       string
		weekly     bool
		reset, now int64
		want       Window
	}{
		{"five-future", false, 1000, 999, Window{42, 1000, 1}},
		{"five-expired", false, 1000, 1001, Window{0, 0, 1}},
		{"five-boundary", false, 1000, 1000, Window{0, 0, 1}},
		{"weekly-just-expired", true, 1000, 1001, Window{0, 1000 + week, 1}},
		{"weekly-one-week", true, 1000, 1000 + week + 1, Window{0, 1000 + 2*week, 1}},
		{"weekly-three-weeks", true, 1000, 1000 + 3*week + 1, Window{0, 1000 + 4*week, 1}},
		{"five-unknown", false, 0, timestamp, Window{42, 0, 1}},
		{"weekly-unknown", true, 0, timestamp, Window{42, 0, 1}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			original := Window{42, tt.reset, 1}
			w := Windows{FiveHour: &original}
			if tt.weekly {
				w = Windows{SevenDay: &original}
			}
			got := Effective(w, tt.now)
			result, absent := got.FiveHour, got.SevenDay
			if tt.weekly {
				result, absent = got.SevenDay, got.FiveHour
			}
			if result == nil || *result != tt.want || absent != nil || original != (Window{42, tt.reset, 1}) {
				t.Fatalf("wrong effective window: %+v", got)
			}
		})
	}
}

// Invariant 2: pace uses percentage points and suppresses unknown resets and the first day.
func TestPace(t *testing.T) {
	for _, tt := range []struct {
		name    string
		window  *Window
		defined bool
		want    float64
	}{
		{"schedule", &Window{50, timestamp + week/2, 0}, true, 0},
		{"ahead", &Window{70, timestamp + week/2, 0}, true, 20},
		{"behind", &Window{30, timestamp + week/2, 0}, true, -20},
		{"early", &Window{50, timestamp + week - 86399, 0}, false, 0},
		{"day-boundary", &Window{100.0 / 7, timestamp + week - 86400, 0}, true, 0},
		{"unknown", &Window{50, 0, 0}, false, 0},
		{"missing", nil, false, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := Pace(tt.window, timestamp)
			if (got != nil) != tt.defined || got != nil && math.Abs(*got-tt.want) > 1e-9 {
				t.Fatal("wrong pace")
			}
		})
	}
}

// Invariant 3: each attribution rule has its own case, including ambiguous fingerprints and rollover.
func TestRecordAttribution(t *testing.T) {
	reset := timestamp + week/2
	for _, tt := range []struct {
		name                  string
		first, fresh, accept  bool
		liveReset, otherReset int64
		switched              int64
		noWeekly              bool
	}{
		{name: "first-unknown", first: true},
		{name: "changed-unknown", fresh: true, accept: true},
		{name: "unchanged-unknown"},
		{name: "fresh-foreign", fresh: true, otherReset: reset},
		{name: "confirmed-unchanged", liveReset: reset, accept: true},
		{name: "confirmed-first", first: true, liveReset: reset, accept: true},
		{name: "cache-window", fresh: true, switched: timestamp - 89},
		{name: "cache-boundary", fresh: true, switched: timestamp - 90},
		{name: "cache-expired", fresh: true, switched: timestamp - 91, accept: true},
		{name: "confirmed-during-cache", liveReset: reset, switched: timestamp, accept: true},
		{name: "fingerprint-mismatch-fresh", fresh: true, liveReset: reset + 1000, accept: true},
		{name: "fingerprint-mismatch-unchanged", liveReset: reset + 1000},
		{name: "weekly-missing-fresh", fresh: true, noWeekly: true, accept: true},
		{name: "weekly-missing-unchanged", noWeekly: true},
		{name: "foreign-tolerance", fresh: true, otherReset: reset + 120},
		{name: "outside-tolerance", fresh: true, otherReset: reset + 121, accept: true},
		{name: "ambiguous", fresh: true, liveReset: reset, otherReset: reset + 60},
		{name: "foreign-after-rollover", fresh: true, otherReset: reset - 3*week},
		{name: "confirmed-after-rollover", liveReset: reset - week, accept: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := store(t)
			managed := map[string]bool{"live": true, "other": true}
			input := sample(42, reset)
			if tt.noWeekly {
				input.RateLimits.SevenDay = nil
			}
			if !tt.first {
				if err := s.Record(input, "live", managed, timestamp-200); err != nil {
					t.Fatal(err)
				}
			}
			state := read(t, s)
			state.LastSwitchAt = tt.switched
			state.Accounts["live"] = Account{Windows: Windows{SevenDay: &Window{10, tt.liveReset, timestamp - 300}}}
			state.Accounts["other"] = Account{Windows: Windows{SevenDay: &Window{20, tt.otherReset, timestamp - 300}}}
			save(t, s, state)
			if tt.fresh {
				input.RateLimits.FiveHour.Used++
			}
			if err := s.Record(input, "live", managed, timestamp); err != nil {
				t.Fatal(err)
			}
			got := read(t, s)
			live := got.Accounts["live"]
			if (live.Source == "statusline") != tt.accept || !reflect.DeepEqual(got.Accounts["other"], state.Accounts["other"]) {
				t.Fatal("wrong attribution or foreign account changed")
			}
			if tt.accept && (live.FiveHour == nil || live.FiveHour.Used != input.RateLimits.FiveHour.Used || live.FiveHour.SeenAt != timestamp) {
				t.Fatal("accepted sample not recorded")
			}
			if !tt.accept && !reflect.DeepEqual(live, state.Accounts["live"]) {
				t.Fatal("dropped sample changed live usage")
			}
			// A session is re-stamped only when first seen or changed (hourly otherwise).
			stamp := int64(timestamp - 200)
			if tt.first || tt.fresh {
				stamp = timestamp
			}
			if got.Sessions["session"].SeenAt != stamp || len(got.Sessions["session"].Digest) != 64 {
				t.Fatal("session stamp wrong for this sample")
			}
		})
	}
}

// Invariant 3: idle A samples never contaminate B, including a fresh or newly opened idle session.
func TestPostSwitchIdleSession(t *testing.T) {
	s := store(t)
	managed := map[string]bool{"a": true, "b": true}
	a := sample(10, timestamp+1000)
	if err := s.Record(a, "a", managed, timestamp-200); err != nil {
		t.Fatal(err)
	}
	a.RateLimits.FiveHour.Used++
	if err := s.Record(a, "a", managed, timestamp-199); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkSwitch(timestamp); err != nil {
		t.Fatal(err)
	}
	for i, at := range []int64{timestamp + 1, timestamp + 91, timestamp + 200} {
		if i == 1 {
			a.RateLimits.FiveHour.Used++
		} else if i == 2 {
			a.SessionID = "new-idle-session"
		}
		if err := s.Record(a, "b", managed, at); err != nil {
			t.Fatal(err)
		}
		if _, exists := read(t, s).Accounts["b"]; exists {
			t.Fatal("idle A numbers were attributed to B")
		}
	}
}

// Invariant 3: the digest ignores JSON spelling but includes both windows' usage and resets.
func TestSampleDigest(t *testing.T) {
	for _, field := range []string{"same-values", "five-used", "five-reset", "weekly-used", "weekly-reset"} {
		t.Run(field, func(t *testing.T) {
			s := store(t)
			managed := map[string]bool{"live": true}
			var first, next Sample
			if json.Unmarshal([]byte(`{"session_id":"s","rate_limits":{"five_hour":{"used_percentage":42,"resets_at":1792080000},"seven_day":{"used_percentage":61.5,"resets_at":1792400000}}}`), &first) != nil ||
				json.Unmarshal([]byte(`{"rate_limits":{"seven_day":{"resets_at":1792400000,"used_percentage":61.50},"five_hour":{"resets_at":1792080000,"used_percentage":42.0}},"session_id":"s","ignored":true}`), &next) != nil {
				t.Fatal("invalid fixture")
			}
			if err := s.Record(first, "live", managed, timestamp); err != nil {
				t.Fatal(err)
			}
			switch field {
			case "five-used":
				next.RateLimits.FiveHour.Used++
			case "five-reset":
				next.RateLimits.FiveHour.ResetsAt++
			case "weekly-used":
				next.RateLimits.SevenDay.Used++
			case "weekly-reset":
				next.RateLimits.SevenDay.ResetsAt++
			}
			if err := s.Record(next, "live", managed, timestamp); err != nil {
				t.Fatal(err)
			}
			if (len(read(t, s).Accounts) != 0) != (field != "same-values") {
				t.Fatal("digest omitted a value or depended on JSON spelling")
			}
		})
	}
}

func TestRecordPartialWindows(t *testing.T) {
	s := store(t)
	managed := map[string]bool{"live": true}
	input := sample(42, 0)
	input.RateLimits.SevenDay = nil
	for range 2 {
		if err := s.Record(input, "live", managed, timestamp); err != nil {
			t.Fatal(err)
		}
		input.RateLimits.FiveHour.Used++
	}
	a := read(t, s).Accounts["live"]
	if a.FiveHour == nil || a.FiveHour.Used != 43 || a.SevenDay != nil {
		t.Fatal("missing weekly window became zero usage")
	}
	input.RateLimits.SevenDay = &Reading{61.5, timestamp + 1000}
	input.RateLimits.FiveHour = nil
	if err := s.Record(input, "live", managed, timestamp); err != nil {
		t.Fatal(err)
	}
	a = read(t, s).Accounts["live"]
	if a.FiveHour.Used != 43 || a.SevenDay.Used != 61.5 {
		t.Fatal("partial sample erased an existing window")
	}
}

// Invariant 4: unchanged data in the same second preserves the file inode and mtime.
func TestRecordUnchangedWritesNothing(t *testing.T) {
	s := store(t)
	managed := map[string]bool{"live": true}
	input := sample(42, timestamp+1000)
	state := read(t, s)
	state.Accounts["live"] = Account{Windows: Windows{SevenDay: &Window{1, timestamp + 1000, 1}}}
	save(t, s, state)
	if err := s.Record(input, "live", managed, timestamp); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.Directory, "usage.json")
	old := time.Unix(100, 0)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	if err := s.Record(input, "live", managed, timestamp); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || !after.ModTime().Equal(old) || after.Mode().Perm() != 0600 {
		t.Fatal("identical input rewrote usage")
	}
	// Timer re-renders of unchanged numbers inside a minute write nothing either.
	if err := s.Record(input, "live", managed, timestamp+59); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.Stat(path); !after.ModTime().Equal(old) {
		t.Fatal("unchanged re-render within a minute rewrote usage")
	}
	// After a minute the confirmed reading refreshes its data age; the session stays hourly.
	if err := s.Record(input, "live", managed, timestamp+61); err != nil {
		t.Fatal(err)
	}
	state = read(t, s)
	if state.Accounts["live"].SevenDay.SeenAt != timestamp+61 || state.Sessions["session"].SeenAt != timestamp {
		t.Fatal("data age or session stamp refreshed at the wrong cadence")
	}
	if err := s.Record(input, "live", managed, timestamp+3600); err != nil || read(t, s).Sessions["session"].SeenAt != timestamp+3600 {
		t.Fatal("unchanged session was not re-stamped after an hour")
	}
}

// Invariant 5: sessions not seen for 24h are pruned while current heartbeats survive.
func TestPruneSessions(t *testing.T) {
	s := store(t)
	managed := map[string]bool{"live": true}
	if err := s.Record(sample(1, 0), "live", managed, timestamp-86400); err != nil {
		t.Fatal(err)
	}
	state := read(t, s)
	state.Sessions["stale"] = Session{"old", timestamp - 86401}
	state.Sessions["boundary"] = Session{"old", timestamp - 86400}
	state.Sessions["recent"] = Session{"old", timestamp - 86399}
	save(t, s, state)
	if err := s.Record(sample(2, 0), "live", managed, timestamp); err != nil {
		t.Fatal(err)
	}
	got := read(t, s)
	if len(got.Sessions) != 2 || got.Sessions["recent"].SeenAt == 0 || got.Sessions["session"].SeenAt != timestamp {
		t.Fatal("stale session survived or active session disappeared")
	}
}

func TestIgnoredSamples(t *testing.T) {
	for _, input := range []Sample{{}, {SessionID: "s"}, {SessionID: "s", RateLimits: &Limits{}}, sample(-1, 0), sample(101, 0), sample(1, -1)} {
		s := store(t)
		_ = s.Record(input, "live", map[string]bool{"live": true}, timestamp)
		if _, err := os.Stat(s.Directory); !os.IsNotExist(err) {
			t.Fatal("ignored or invalid sample created state")
		}
	}
	s := store(t)
	if err := s.Record(sample(1, 0), "unmanaged", nil, timestamp); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.Directory); !os.IsNotExist(err) {
		t.Fatal("unmanaged sample created state")
	}
}

func TestUsageLockDeadline(t *testing.T) {
	s := store(t)
	if err := statehome.PrivateDir(s.Directory); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(s.Directory, "usage.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	clock := time.Unix(timestamp, 0)
	oldNow, oldPause := now, lockPause
	now = func() time.Time { return clock }
	lockPause = func(delay time.Duration) { clock = clock.Add(delay) }
	t.Cleanup(func() { now, lockPause = oldNow, oldPause })
	if err := s.Record(sample(1, 0), "live", map[string]bool{"live": true}, timestamp); err == nil || clock.Unix() != timestamp+2 {
		t.Fatal("contended flock ignored its two-second deadline")
	}
	if _, err := os.Stat(filepath.Join(s.Directory, "usage.json")); !os.IsNotExist(err) {
		t.Fatal("contended writer touched usage")
	}
}

func TestInvalidUsagePreserved(t *testing.T) {
	for _, data := range []string{`null`, `{}`, `{"schemaVersion":2,"accounts":{},"sessions":{}}`, `{"schemaVersion":1,"accounts":null,"sessions":{}}`, `torn`} {
		s := store(t)
		path := filepath.Join(s.Directory, "usage.json")
		if err := statehome.AtomicWrite(path, []byte(data)); err != nil {
			t.Fatal(err)
		}
		if err := s.MarkSwitch(timestamp); err == nil {
			t.Fatal("invalid usage accepted")
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != data {
			t.Fatal("invalid usage overwritten")
		}
	}
}

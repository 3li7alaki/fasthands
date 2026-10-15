package accounts

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"fasthands/internal/usage"
)

// Slice 5a invariant 9: a complete replacement order is atomic and survives re-add.
func TestSetPriority(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			f := setupSwitch(t, platform)
			t.Setenv("TZ", "UTC")
			for _, aliases := range [][]string{{"b", "a"}, {"a"}, nil} {
				if err := f.m.SetPriority(aliases); err != nil {
					t.Fatal(err)
				}
				db, err := f.m.read()
				if err != nil {
					t.Fatal(err)
				}
				for _, a := range db.Accounts {
					want := 0
					for i, alias := range aliases {
						if alias == a.Alias {
							want = i + 1
						}
					}
					if a.Priority != want {
						t.Fatal("wrong priority or unlisted rank survived")
					}
				}
			}
			if err := f.m.SetPriority([]string{"b", "a"}); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.m.Paths.State, "accounts.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, aliases := range [][]string{{"a", "missing"}, {"a", "a"}} {
				err := f.m.SetPriority(aliases)
				want := aliases[len(aliases)-1]
				if err == nil || !strings.Contains(err.Error(), `"`+want+`"`) {
					t.Fatal("invalid order did not name alias")
				}
				after, readErr := os.ReadFile(path)
				afterInfo, statErr := os.Stat(path)
				if readErr != nil || statErr != nil || string(before) != string(after) || !os.SameFile(info, afterInfo) || !info.ModTime().Equal(afterInfo.ModTime()) {
					t.Fatal("invalid priority order wrote metadata")
				}
			}
			if _, err := f.m.Add(capture("id-a", "a@example.com"), "a", true); err != nil {
				t.Fatal(err)
			}
			db, err := f.m.read()
			if err != nil || db.Accounts["id-a"].Priority != 2 {
				t.Fatal("re-add erased priority")
			}
		})
	}
}

func TestPickable(t *testing.T) {
	m := manager(t.TempDir())
	db := database{SchemaVersion: 1, Accounts: map[string]Account{
		"a": {Alias: "a", RateLimitTier: "default_claude_max_20x", Priority: 2},
		"b": {Alias: "b", RateLimitTier: "default_claude_max_5x", Priority: 1},
		"c": {Alias: "c", RateLimitTier: "unknown"},
		"d": {Alias: "d"},
	}}
	if err := m.write(db); err != nil {
		t.Fatal(err)
	}
	windows := usage.Windows{SevenDay: &usage.Window{Used: 50, ResetsAt: fetchNow + 1000}}
	state := usage.State{Accounts: map[string]usage.Account{"a": {Windows: windows}, "unmanaged": {Windows: windows}}}
	list, err := m.Pickable(state)
	if err != nil || len(list) != 4 {
		t.Fatalf("pickable failed: %v", err)
	}
	for i, wantWeight := range []float64{20, 5, 1, 1} {
		a := list[i]
		if a.Weight != wantWeight || a.Priority != db.Accounts[a.ID].Priority || a.Alias != db.Accounts[a.ID].Alias || !reflect.DeepEqual(a.Windows, state.Accounts[a.ID].Windows) {
			t.Fatal("pickable lost metadata, windows, or plan weight")
		}
	}
	if err := os.WriteFile(filepath.Join(m.Paths.State, "accounts.json"), []byte("torn"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Pickable(state); err == nil {
		t.Fatal("pickable swallowed metadata error")
	}
}

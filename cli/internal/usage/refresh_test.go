package usage

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"fasthands/internal/oauth"
)

// Slice 4b2 invariants 7, 8: refresh state survives all existing usage writers and disappears when cleared.
func TestSaveRefreshPreservesUsage(t *testing.T) {
	s := store(t)
	if err := s.SaveFetched("a", oauth.Usage{SevenDay: &oauth.Window{Used: 42, ResetsAt: timestamp + 1000}}, timestamp); err != nil {
		t.Fatal(err)
	}
	before := read(t, s).Accounts["a"]
	if err := s.SaveRefresh("a", "0123456789abcdef", timestamp+600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Reserve("a", timestamp); err != nil {
		t.Fatal(err)
	}
	if err := s.Block("a", timestamp+3600); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(sample(43, timestamp+1000), "a", map[string]bool{"a": true}, timestamp); err != nil {
		t.Fatal(err)
	}
	a := read(t, s).Accounts["a"]
	if a.DeadRefresh != "0123456789abcdef" || a.RefreshRetryAt != timestamp+600 || len(a.Requests) != 1 || a.BlockedUntil != timestamp+3600 || a.SevenDay.Used != 43 || before.SevenDay.Used != 42 {
		t.Fatal("existing usage writers erased refresh state or windows")
	}
	var workers sync.WaitGroup
	for _, id := range []string{"a", "b"} {
		workers.Go(func() {
			if err := s.SaveRefresh(id, "", 0); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	got := read(t, s).Accounts["a"]
	a.DeadRefresh, a.RefreshRetryAt = "", 0
	if !reflect.DeepEqual(got, a) {
		t.Fatal("clearing refresh state erased other account data")
	}
	data, err := os.ReadFile(filepath.Join(s.Directory, "usage.json"))
	if err != nil || strings.Contains(string(data), "deadRefresh") || strings.Contains(string(data), "refreshRetryAt") {
		t.Fatal("empty refresh state was not omitted")
	}
}

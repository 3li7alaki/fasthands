package usage

import (
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"fasthands/internal/oauth"
)

// Slice 4b1 invariant 4: the persisted budget counts attempts in a trailing hour.
func TestReserveBudget(t *testing.T) {
	s := store(t)
	for i := range 20 {
		if ok, reason, err := s.Reserve("a", timestamp+int64(i)); err != nil || !ok || reason != "" {
			t.Fatalf("reservation %d failed: %s, %v", i+1, reason, err)
		}
	}
	s = Store{Directory: s.Directory}
	if ok, reason, err := s.Reserve("a", timestamp+3600); err != nil || ok || reason != "request budget spent (20 per hour)" {
		t.Fatal("twenty-first attempt bypassed persisted budget")
	}
	if ok, _, err := s.Reserve("a", timestamp+3601); err != nil || !ok {
		t.Fatal("aged-out attempt did not restore capacity")
	}
	if ok, _, err := s.Reserve("b", timestamp+3601); err != nil || !ok {
		t.Fatal("accounts shared a budget")
	}
	requests := read(t, s).Accounts["a"].Requests
	if len(requests) != 20 || requests[0] != timestamp+1 || requests[19] != timestamp+3601 {
		t.Fatal("requests not pruned or ordered oldest first")
	}
}

func TestReserveConcurrent(t *testing.T) {
	s := store(t)
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() {
			if _, _, err := s.Reserve("a", timestamp); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	if len(read(t, s).Accounts["a"].Requests) != 20 {
		t.Fatal("concurrent reservations overspent or lost budget")
	}
}

// Slice 4b1 invariant 5: blocks only extend and refusals spend no requests.
func TestBlockMonotonic(t *testing.T) {
	s := store(t)
	for _, until := range []int64{timestamp + 3600, timestamp + 1000} {
		if err := s.Block("a", until); err != nil {
			t.Fatal(err)
		}
	}
	until := timestamp + 3600
	want := "blocked until " + time.Unix(until, 0).Local().Format("15:04")
	if ok, reason, err := s.Reserve("a", timestamp); err != nil || ok || reason != want {
		t.Fatal("block was shortened or ignored")
	}
	if a := read(t, s).Accounts["a"]; a.BlockedUntil != until || len(a.Requests) != 0 {
		t.Fatal("blocked reservation changed request history")
	}
	if ok, _, err := s.Reserve("a", until); err != nil || !ok {
		t.Fatal("block did not end at deadline")
	}
}

// Slice 4b1 invariant 7: fetched windows replace old data and share weekly rollover math.
func TestSaveFetchedAndModelRollover(t *testing.T) {
	s := store(t)
	if _, _, err := s.Reserve("a", timestamp); err != nil {
		t.Fatal(err)
	}
	u := oauth.Usage{FiveHour: &oauth.Window{Used: 20, ResetsAt: timestamp + 100},
		SevenDay: &oauth.Window{Used: 30, ResetsAt: timestamp - 1}, Models: map[string]*oauth.Window{"Fable": {Used: 40, ResetsAt: timestamp - 1}}}
	if err := s.SaveFetched("a", u, timestamp); err != nil {
		t.Fatal(err)
	}
	a := read(t, s).Accounts["a"]
	if a.Source != "api" || a.FiveHour.SeenAt != timestamp || a.SevenDay.SeenAt != timestamp || a.Models["Fable"].SeenAt != timestamp || len(a.Requests) != 1 {
		t.Fatal("fetched windows lost timestamps, source or budget")
	}
	effective := Effective(a.Windows, timestamp)
	if *effective.Models["Fable"] != *effective.SevenDay || effective.Models["Fable"].ResetsAt != timestamp-1+week || a.Models["Fable"].Used != 40 {
		t.Fatal("models did not use pure weekly rollover")
	}
	if err := s.SaveFetched("a", oauth.Usage{FiveHour: &oauth.Window{Used: 10}}, timestamp+1); err != nil {
		t.Fatal(err)
	}
	a = read(t, s).Accounts["a"]
	if a.FiveHour.Used != 10 || a.SevenDay != nil || len(a.Models) != 0 || !reflect.DeepEqual(a.Requests, []int64{timestamp}) {
		t.Fatal("omitted windows survived replacement or budget changed")
	}
	if err := s.SaveFetched("a", oauth.Usage{}, timestamp+2); err != nil || read(t, s).Accounts["a"].FiveHour != nil {
		t.Fatal("omitted five-hour window survived replacement")
	}
}

func TestReserveWriteFailure(t *testing.T) {
	s := store(t)
	if err := os.MkdirAll(filepath.Join(s.Directory, "usage.json"), 0700); err != nil {
		t.Fatal(err)
	}
	if ok, _, err := s.Reserve("a", timestamp); err == nil || ok {
		t.Fatal("reservation authorized HTTP without persisting")
	}
}

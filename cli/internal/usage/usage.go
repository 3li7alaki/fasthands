// Package usage attributes passive status line samples and models idle accounts offline.
package usage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"fasthands/internal/statehome"
)

const week int64 = 604800 // U3: weekly resets advance by exactly seven days.

type Window struct {
	Used     float64 `json:"used"`
	ResetsAt int64   `json:"resetsAt"`
	SeenAt   int64   `json:"seenAt"`
}

type Windows struct {
	FiveHour *Window            `json:"fiveHour,omitempty"`
	SevenDay *Window            `json:"sevenDay,omitempty"`
	Models   map[string]*Window `json:"models,omitempty"`
}

type Account struct {
	Windows
	Source       string  `json:"source"`
	Requests     []int64 `json:"requests,omitempty"`
	BlockedUntil int64   `json:"blockedUntil,omitempty"`
}

type Session struct {
	Digest string `json:"digest"`
	SeenAt int64  `json:"seenAt"`
}

type State struct {
	SchemaVersion int                `json:"schemaVersion"`
	LastSwitchAt  int64              `json:"lastSwitchAt"`
	Accounts      map[string]Account `json:"accounts"`
	Sessions      map[string]Session `json:"sessions"`
}

type Reading struct {
	Used     float64 `json:"used_percentage"`
	ResetsAt int64   `json:"resets_at"`
}

type Limits struct {
	FiveHour *Reading `json:"five_hour"`
	SevenDay *Reading `json:"seven_day"`
}

type Sample struct {
	SessionID  string  `json:"session_id"`
	RateLimits *Limits `json:"rate_limits"`
}

// Effective copies both windows so their reset rules cannot diverge between callers.
func Effective(w Windows, now int64) Windows {
	copyWindow := func(stored *Window, weekly bool) *Window {
		if stored == nil {
			return nil
		}
		v := *stored
		if v.ResetsAt != 0 && v.ResetsAt <= now {
			v.Used = 0
			if weekly {
				v.ResetsAt += ((now-v.ResetsAt)/week + 1) * week
			} else {
				v.ResetsAt = 0
			}
		}
		return &v
	}
	result := Windows{FiveHour: copyWindow(w.FiveHour, false), SevenDay: copyWindow(w.SevenDay, true)}
	if len(w.Models) != 0 {
		result.Models = make(map[string]*Window, len(w.Models))
		for name, model := range w.Models {
			result.Models[name] = copyWindow(model, true) // O2: per-model limits are weekly windows too.
		}
	}
	return result
}

func Pace(sevenDay *Window, now int64) *float64 {
	if sevenDay == nil || sevenDay.ResetsAt == 0 {
		return nil
	}
	elapsed := week - (sevenDay.ResetsAt - now)
	// Suppress the first day's misleading pace immediately after a weekly reset.
	if elapsed < 86400 {
		return nil
	}
	pace := sevenDay.Used - 100*float64(elapsed)/float64(week)
	return &pace
}

func (s *State) record(sample Sample, live string, managed map[string]bool, now int64) {
	old, exists := s.Sessions[sample.SessionID]
	canonical, _ := json.Marshal(sample.RateLimits)
	digest := sha256.Sum256(canonical)
	current := Session{hex.EncodeToString(digest[:]), now}
	fresh := exists && old.Digest != current.Digest // Rule 2: a first sample is never fresh.
	// Status lines re-render on a timer: an unchanged session is re-stamped hourly, not
	// per render, so an idle session costs no disk write (pruning only needs 24h).
	if !exists || fresh || now-old.SeenAt >= 3600 {
		s.Sessions[sample.SessionID] = current
	}
	for id, session := range s.Sessions {
		if now-session.SeenAt >= 86400 {
			delete(s.Sessions, id)
		}
	}
	reset := int64(0)
	if sample.RateLimits.SevenDay != nil {
		reset = sample.RateLimits.SevenDay.ResetsAt
	}
	matches := func(id string) bool {
		w := Effective(s.Accounts[id].Windows, now).SevenDay
		return reset != 0 && w != nil && w.ResetsAt != 0 && reset >= w.ResetsAt-120 && reset <= w.ResetsAt+120
	}
	for id := range managed {
		// ponytail: weekly fingerprints within 120s are ambiguous; rule 3 drops matching samples for both accounts.
		if id != live && matches(id) {
			return
		}
	}
	if !matches(live) && (!fresh || now-s.LastSwitchAt <= 90) {
		return // Rule 5: an unconfirmed sample must outlive credential caching after a switch.
	}
	a := s.Accounts[live]
	for _, pair := range []struct {
		reading *Reading
		window  **Window
	}{{sample.RateLimits.FiveHour, &a.FiveHour}, {sample.RateLimits.SevenDay, &a.SevenDay}} {
		if pair.reading == nil {
			continue
		}
		// An unchanged reading refreshes seenAt at most once a minute: data age stays
		// honest for status without a write on every render.
		if w := *pair.window; w != nil && w.Used == pair.reading.Used && w.ResetsAt == pair.reading.ResetsAt && now-w.SeenAt < 60 {
			continue
		}
		*pair.window = &Window{pair.reading.Used, pair.reading.ResetsAt, now}
	}
	a.Source = "statusline"
	s.Accounts[live] = a
}

type Store struct{ Directory string }

func (s Store) Read() (State, error) {
	path := filepath.Join(s.Directory, "usage.json")
	for range 2 { // Readers take no flock; retry once if they catch a torn external write.
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return State{SchemaVersion: 1, Accounts: map[string]Account{}, Sessions: map[string]Session{}}, nil
		}
		if err != nil {
			return State{}, fmt.Errorf("cannot read usage at %q", path)
		}
		var state State
		if json.Unmarshal(data, &state) == nil && state.SchemaVersion == 1 && state.Accounts != nil && state.Sessions != nil {
			return state, nil
		}
	}
	return State{}, fmt.Errorf("invalid usage at %q", path)
}

func (s Store) Record(sample Sample, live string, managed map[string]bool, now int64) error {
	if !managed[live] || sample.SessionID == "" || sample.RateLimits == nil ||
		sample.RateLimits.FiveHour == nil && sample.RateLimits.SevenDay == nil {
		return nil
	}
	for _, w := range []*Reading{sample.RateLimits.FiveHour, sample.RateLimits.SevenDay} {
		if w != nil && (w.Used < 0 || w.Used > 100 || w.ResetsAt < 0) {
			return errors.New("invalid usage sample")
		}
	}
	return s.update(func(state *State) { state.record(sample, live, managed, now) })
}

func (s Store) MarkSwitch(now int64) error {
	return s.update(func(state *State) { state.LastSwitchAt = now })
}

func (s Store) update(change func(*State)) error {
	lock, err := s.lock()
	if err != nil {
		return err
	}
	defer lock.Close() // Closing releases this separate flock, never accounts.lock.
	state, err := s.Read()
	if err != nil {
		return err
	}
	before, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return errors.New("cannot encode usage")
	}
	change(&state)
	after, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return errors.New("cannot encode usage")
	}
	if bytes.Equal(before, after) {
		return nil
	}
	path := filepath.Join(s.Directory, "usage.json")
	if statehome.AtomicWrite(path, append(after, '\n')) != nil {
		return fmt.Errorf("cannot write usage at %q", path)
	}
	return nil
}

var now = time.Now
var lockPause = time.Sleep

func (s Store) lock() (*os.File, error) {
	if err := statehome.PrivateDir(s.Directory); err != nil {
		return nil, fmt.Errorf("cannot create state directory %q", s.Directory)
	}
	path := filepath.Join(s.Directory, "usage.lock")
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("cannot open usage lock at %q", path)
	}
	if err := lock.Chmod(0600); err != nil {
		lock.Close()
		return nil, fmt.Errorf("cannot secure usage lock at %q", path)
	}
	deadline := now().Add(2 * time.Second)
	for {
		err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return lock, nil
		}
		if err != syscall.EINTR && err != syscall.EWOULDBLOCK || !now().Before(deadline) {
			lock.Close()
			return nil, fmt.Errorf("cannot acquire usage lock at %q", path)
		}
		// Nonblocking polling bounds the hook to 2s without leaving a blocked flock goroutine.
		lockPause(min(10*time.Millisecond, deadline.Sub(now())))
	}
}

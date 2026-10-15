package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"fasthands/internal/accounts"
	"fasthands/internal/claudecfg"
	"fasthands/internal/claudesessions"
	"fasthands/internal/picker"
	"fasthands/internal/statehome"
	usageState "fasthands/internal/usage"
)

func priority(m accounts.Manager, aliases []string, jsonMode bool, stdout, stderr io.Writer) int {
	if len(aliases) != 0 {
		if err := m.SetPriority(aliases); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	metadata, err := m.Read()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	ordered := make([]accounts.Account, 0, len(metadata))
	for _, a := range metadata {
		if a.Priority > 0 {
			ordered = append(ordered, a)
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Priority != ordered[j].Priority {
			return ordered[i].Priority < ordered[j].Priority
		}
		return ordered[i].Alias < ordered[j].Alias
	})
	order := make([]string, 0, len(ordered))
	for _, a := range ordered {
		order = append(order, a.Alias)
	}
	if jsonMode {
		return outputJSON(stdout, stderr, struct {
			Priority []string `json:"priority"`
		}{order})
	}
	for _, alias := range order {
		fmt.Fprintln(stdout, alias)
	}
	return 0
}

func readDecision(m accounts.Manager, loc claudecfg.Locations) (picker.Decision, map[string]string, error) {
	state, err := (usageState.Store{Directory: m.Paths.State}).Read()
	if err != nil {
		return picker.Decision{}, nil, err
	}
	list, err := m.Pickable(state)
	if err != nil {
		return picker.Decision{}, nil, err
	}
	live, err := claudecfg.ActiveUUID(loc)
	if err != nil {
		return picker.Decision{}, nil, err
	}
	aliases := make(map[string]string, len(list))
	for _, a := range list {
		aliases[a.ID] = a.Alias
	}
	return picker.Decide(list, live, state.LastSwitchAt, now().Unix()), aliases, nil
}

func pick(m accounts.Manager, auto, jsonMode bool, stdout, stderr io.Writer) int {
	// Auto reports operational failures without failing a hook; only a failed switch exits 1.
	failure := 1
	if auto {
		failure = 0
		lock, err := autoLock(m.Paths.State)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 0
		}
		if lock == nil {
			return 0
		}
		defer lock.Close()
	}
	loc, err := claudecfg.Locate()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return failure
	}
	d, aliases, err := readDecision(m, loc)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return failure
	}
	switched := false
	var warnings []string
	if auto && d.Action == "switch" && !d.Urgent && anyMidTurn(loc) {
		// Each account has its own prompt cache, so a switch costs every open session one
		// uncached request. A non-urgent switch waits until no session is mid-turn, when
		// an idle session's cache has often expired anyway. The hook retries each minute.
		// ponytail: sessions that never go idle defer it until the active account turns
		// urgent at threshold; add a maximum wait if that wastes expiring quota.
		d = picker.Decision{Action: "hold", From: d.From, Reason: "waiting for idle Claude sessions before switching to " + aliases[d.To]}
	}
	if auto && d.Action == "switch" {
		// Rule 5: Fetch owns budgets and idle token rotation; always re-read before acting.
		fetchUsage(m, []string{d.To}, loc, d.From)
		d, aliases, err = readDecision(m, loc)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 0
		}
		if d.Action == "switch" {
			result, err := m.Switch(aliases[d.To], loc, platform, securityPath, accounts.SwitchOptions{Force: true})
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			switched, warnings = result.Switched, result.Warnings
			if switched {
				if err := appendAutoLog(m.Paths.State, result.From, result.To, d.Reason); err != nil {
					warnings = append(warnings, err.Error())
				}
			}
		}
	}
	d.From, d.To = aliases[d.From], aliases[d.To]
	code := 0
	if jsonMode {
		result := struct {
			picker.Decision
			Switched *bool `json:"switched,omitempty"`
			Auto     *bool `json:"auto,omitempty"`
		}{Decision: d}
		if auto {
			result.Switched = &switched
		} else {
			enabled := autoEnabled(m.Paths.State)
			result.Auto = &enabled
		}
		code = outputJSON(stdout, stderr, result)
	} else if d.Action == "switch" {
		fmt.Fprintf(stdout, "switch %s -> %s: %s\n", d.From, d.To, d.Reason)
	} else {
		fmt.Fprintln(stdout, "hold: "+d.Reason)
	}
	if !auto && !jsonMode && !autoEnabled(m.Paths.State) {
		fmt.Fprintln(stdout, "auto switching off")
	}
	for _, warning := range warnings {
		fmt.Fprintln(stderr, "warning: "+warning)
	}
	if auto {
		return 0
	}
	return code
}

// anyMidTurn counts every session, the one that spawned this run included: its own
// cache is lost by a switch just the same. An unreadable scan counts as busy.
func anyMidTurn(loc claudecfg.Locations) bool {
	sessions, err := claudesessions.Scan(loc.ConfigHome)
	return err != nil || len(claudesessions.MidTurn(sessions)) != 0
}

func autoLock(directory string) (*os.File, error) {
	if err := statehome.PrivateDir(directory); err != nil {
		return nil, fmt.Errorf("cannot create state directory %q", directory)
	}
	path := filepath.Join(directory, "auto.lock")
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("cannot open auto lock at %q", path)
	}
	for {
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot acquire auto lock at %q", path)
	}
	if err := lock.Chmod(0600); err != nil {
		lock.Close()
		return nil, fmt.Errorf("cannot secure auto lock at %q", path)
	}
	return lock, nil
}

func appendAutoLog(directory, from, to, reason string) error {
	path := filepath.Join(directory, "auto.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("cannot open auto log at %q", path)
	}
	defer f.Close()
	if f.Chmod(0600) != nil {
		return fmt.Errorf("cannot secure auto log at %q", path)
	}
	if _, err := fmt.Fprintf(f, "%s\t%s\t%s\t%s\n", now().UTC().Format(time.RFC3339), from, to, reason); err != nil {
		return fmt.Errorf("cannot append auto log at %q", path)
	}
	return nil
}

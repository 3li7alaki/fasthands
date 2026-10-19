package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"fasthands/internal/accounts"
	"fasthands/internal/claudecfg"
	"fasthands/internal/statehome"
	usageState "fasthands/internal/usage"
)

var now = time.Now

func statusline(stdin io.Reader, stdout io.Writer) {
	// A status line must never break Claude's display; only this hook swallows errors.
	loc, err := claudecfg.Locate()
	if err != nil {
		return
	}
	live, err := claudecfg.ActiveUUID(loc)
	if err != nil {
		return
	}
	paths, err := statehome.Locate()
	if err != nil {
		return
	}
	metadata, err := (accounts.Manager{Paths: paths}).Pickable(usageState.State{})
	if err != nil {
		return
	}
	managed := make(map[string]bool, len(metadata))
	var alias string
	for _, a := range metadata {
		managed[a.ID] = true
		if a.ID == live {
			alias = a.Alias
		}
	}
	if !managed[live] {
		return
	}
	fmt.Fprintln(stdout, alias)
	const limit = 1 << 20 // Bound untrusted status line stdin to 1 MiB.
	data, err := io.ReadAll(io.LimitReader(stdin, limit+1))
	var sample usageState.Sample
	if err != nil || len(data) > limit || json.Unmarshal(data, &sample) != nil {
		return
	}
	_ = (usageState.Store{Directory: paths.State}).Record(sample, live, managed, now().Unix())
	triggerAuto(paths.State, metadata, live)
}

type statusWindow struct {
	Used     float64 `json:"used"`
	ResetsAt int64   `json:"resetsAt"`
	Known    bool    `json:"known"`
}

type weeklyWindow struct {
	statusWindow
	Pace *float64 `json:"pace"`
}

type statusAccount struct {
	Alias            string                   `json:"alias"`
	AccountUUID      string                   `json:"accountUuid"`
	Active           bool                     `json:"active"`
	Disabled         bool                     `json:"disabled,omitempty"`
	FiveHour         *statusWindow            `json:"fiveHour"`
	SevenDay         *weeklyWindow            `json:"sevenDay"`
	SeenAt           *int64                   `json:"seenAt"`
	Source           *string                  `json:"source"`
	SubscriptionType string                   `json:"subscriptionType"`
	RateLimitTier    string                   `json:"rateLimitTier"`
	Models           map[string]*statusWindow `json:"models"`
	Note             string                   `json:"note"`
}

func status(m accounts.Manager, jsonMode bool, stdout, stderr io.Writer) int {
	metadata, err := m.Read()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	var live string
	var loc claudecfg.Locations
	if len(metadata) != 0 {
		loc, err = claudecfg.Locate()
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		live, err = claudecfg.ActiveUUID(loc)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	state, err := (usageState.Store{Directory: m.Paths.State}).Read()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	timestamp := now().Unix()
	var stale []string
	for id, a := range metadata {
		if a.Disabled {
			continue
		}
		seen := newestSeenAt(state.Accounts[id].Windows)
		if seen == 0 || timestamp-seen > 600 {
			stale = append(stale, id)
		}
	}
	notes := make(map[string]string, len(stale))
	if len(stale) != 0 {
		for _, result := range fetchUsage(m, stale, loc, live) {
			notes[result.AccountUUID] = result.Skipped
			if result.Error != "" {
				notes[result.AccountUUID] = result.Error
			}
		}
		if fetched, err := (usageState.Store{Directory: m.Paths.State}).Read(); err == nil {
			state = fetched
		}
	}
	list := make([]statusAccount, 0, len(metadata))
	for id, a := range metadata {
		saved := state.Accounts[id]
		w := usageState.Effective(saved.Windows, timestamp)
		row := statusAccount{Alias: a.Alias, AccountUUID: id, Active: id == live,
			Disabled:         a.Disabled,
			SubscriptionType: a.SubscriptionType, RateLimitTier: a.RateLimitTier,
			Models: map[string]*statusWindow{}, Note: notes[id]}
		if a.Disabled {
			row.Note = "disabled"
		}
		window := func(w *usageState.Window) *statusWindow {
			if w == nil {
				return nil
			}
			if row.SeenAt == nil || w.SeenAt > *row.SeenAt {
				seen := w.SeenAt
				row.SeenAt = &seen
			}
			row.Source = &saved.Source
			return &statusWindow{w.Used, w.ResetsAt, w.ResetsAt != 0}
		}
		row.FiveHour = window(w.FiveHour)
		if weekly := window(w.SevenDay); weekly != nil {
			row.SevenDay = &weeklyWindow{*weekly, usageState.Pace(w.SevenDay, timestamp)}
		}
		for name, model := range w.Models {
			if model != nil {
				row.Models[name] = window(model)
			}
		}
		list = append(list, row)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Active != list[j].Active {
			return list[i].Active
		}
		return list[i].Alias < list[j].Alias
	})
	last := lastAutoSwitch(m.Paths.State)
	if jsonMode {
		return outputJSON(stdout, stderr, struct {
			Accounts       []statusAccount `json:"accounts"`
			LastAutoSwitch *autoSwitch     `json:"lastAutoSwitch"`
		}{list, last})
	}
	for _, row := range list {
		active, five, weekly, pace, age := "", "-\t-", "-\t-", "-", "never"
		if row.Active {
			active = "*"
		}
		format := func(w *statusWindow, layout string) string {
			reset := "-"
			if w.Known {
				reset = time.Unix(w.ResetsAt, 0).Local().Format(layout)
			}
			return fmt.Sprintf("%g%%\t%s", w.Used, reset)
		}
		if row.FiveHour != nil {
			five = format(row.FiveHour, "15:04")
		}
		if row.SevenDay != nil {
			weekly = format(&row.SevenDay.statusWindow, "Mon 15:04")
			if row.SevenDay.Pace != nil {
				pace = fmt.Sprintf("%+.1f", *row.SevenDay.Pace)
			}
		}
		if row.SeenAt != nil {
			seconds := max(0, timestamp-*row.SeenAt)
			age = fmt.Sprintf("%ds ago", seconds)
			for _, unit := range []struct {
				size int64
				name string
			}{{86400, "d"}, {3600, "h"}, {60, "m"}} {
				if seconds >= unit.size {
					age = fmt.Sprintf("%d%s ago", seconds/unit.size, unit.name)
					break
				}
			}
		}
		plan := strings.TrimSpace(row.SubscriptionType + " " + row.RateLimitTier)
		if plan == "" {
			plan = "-"
		}
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", row.Alias, active, five, weekly, pace, age, plan, row.Note)
	}
	if last != nil {
		fmt.Fprintf(stdout, "last auto switch: %s %s -> %s (%s)\n", time.Unix(last.At, 0).Local().Format("Mon 15:04"), last.From, last.To, last.Reason)
	}
	return 0
}

func newestSeenAt(w usageState.Windows) int64 {
	var seen int64
	for _, window := range []*usageState.Window{w.FiveHour, w.SevenDay} {
		if window != nil {
			seen = max(seen, window.SeenAt)
		}
	}
	for _, window := range w.Models {
		if window != nil {
			seen = max(seen, window.SeenAt)
		}
	}
	return seen
}

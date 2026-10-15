// Package picker applies docs/picker.md without I/O or an implicit clock.
package picker

import (
	"fmt"
	"sort"
	"time"

	"fasthands/internal/usage"
)

const (
	threshold          = 0.90
	hysteresis         = 0.10
	cooldown     int64 = 300
	tie          int64 = 3600
	escapeMargin int64 = 300
)

type Account struct {
	ID, Alias string
	Windows   usage.Windows
	Weight    float64
	Priority  int
}

type Decision struct {
	Action string `json:"action"`
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason"`
	// Urgent marks switches forced by the active account's usage (threshold, rule 4).
	// Other switches only chase an earlier reset and can wait for idle sessions.
	Urgent bool `json:"urgent"`
}

type evaluated struct {
	Account
	binding  usage.Window
	window   string
	eligible bool
}

func evaluate(a Account, now int64) evaluated {
	a.Windows = usage.Effective(a.Windows, now)
	// Rule 1: start below 0% so a known unused window still supplies its reset.
	e := evaluated{Account: a, binding: usage.Window{Used: -1}}
	include := func(w *usage.Window, name string) {
		if w != nil && w.Used > e.binding.Used {
			e.binding, e.window = *w, name
		}
	}
	include(a.Windows.FiveHour, "5h")
	include(a.Windows.SevenDay, "weekly")
	// Rule 1: unused models do not bind; sorted names keep equal-usage ties deterministic.
	names := make([]string, 0, len(a.Windows.Models))
	for name := range a.Windows.Models {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if w := a.Windows.Models[name]; w != nil && w.Used > 0 {
			include(w, fmt.Sprintf("%q", name)) // Rule 1: quote model names to keep reasons on one line.
		}
	}
	e.eligible = a.Windows.SevenDay != nil && e.binding.Used/100 < threshold-hysteresis
	return e
}

func rank(a evaluated) uint {
	if a.Priority > 0 {
		return uint(a.Priority)
	}
	return ^uint(0) // Rule 2: unranked sorts after every positive int rank.
}

func headroom(a evaluated, weekly bool) float64 {
	used := a.binding.Used
	if weekly {
		used = a.Windows.SevenDay.Used
	}
	return (1 - used/100) * a.Weight
}

func prefer(a, b evaluated, weekly bool) bool {
	// Rules 2/4: eligible ties prioritize rank; fallback prioritizes binding headroom.
	if weekly && rank(a) != rank(b) {
		return rank(a) < rank(b)
	}
	if headroom(a, weekly) != headroom(b, weekly) {
		return headroom(a, weekly) > headroom(b, weekly)
	}
	if rank(a) != rank(b) {
		return rank(a) < rank(b)
	}
	return a.Alias < b.Alias
}

func bestEligible(others []evaluated) *evaluated {
	var earliest int64
	for _, a := range others {
		if a.eligible {
			reset := a.Windows.SevenDay.ResetsAt
			if reset != 0 && (earliest == 0 || reset < earliest) {
				earliest = reset
			}
		}
	}
	var best *evaluated
	for i := range others {
		a := &others[i]
		if !a.eligible {
			continue
		}
		reset := a.Windows.SevenDay.ResetsAt
		// Rule 2: anchor the tie set once; pairwise "within tie" is not transitive.
		if earliest != 0 && (reset == 0 || reset-earliest > tie) {
			continue
		}
		if best == nil || prefer(*a, *best, true) {
			best = a
		}
	}
	return best
}

func Decide(accounts []Account, active string, lastSwitchAt, now int64) Decision {
	d := Decision{Action: "hold", From: active, Reason: "rule 3: active account is not managed"}
	var current *evaluated
	others := make([]evaluated, 0, len(accounts))
	for _, a := range accounts {
		e := evaluate(a, now)
		if a.ID == active {
			current = &e
		} else {
			others = append(others, e)
		}
	}
	if current == nil {
		return d
	}
	if len(others) == 0 {
		d.Reason = "rule 3: no other managed account"
		return d
	}
	a := *current
	if now-lastSwitchAt < cooldown && a.binding.Used < 100 {
		d.Reason = fmt.Sprintf("rule 3: cooldown (%ds left)", cooldown-(now-lastSwitchAt))
		return d
	}
	switchTo := func(b evaluated, reason string) Decision {
		return Decision{Action: "switch", From: active, To: b.ID, Reason: reason}
	}
	urgent := func(b evaluated, reason string) Decision {
		d := switchTo(b, reason)
		d.Urgent = true
		return d
	}
	b := bestEligible(others)
	if a.binding.Used/100 >= threshold {
		if b != nil {
			return urgent(*b, fmt.Sprintf("rule 3: %s at %g%% (%s); %s eligible, weekly reset order", a.Alias, a.binding.Used, a.window, b.Alias))
		}
		var room, sooner *evaluated
		for i := range others {
			c := &others[i]
			if c.Windows.SevenDay == nil {
				continue // Rule 1: unknown accounts are never targets, including rule 4.
			}
			if c.binding.Used/100 < threshold && (room == nil || prefer(*c, *room, false)) {
				room = c
			}
			if c.binding.ResetsAt != 0 && (sooner == nil || c.binding.ResetsAt < sooner.binding.ResetsAt ||
				c.binding.ResetsAt == sooner.binding.ResetsAt && (rank(*c) < rank(*sooner) || rank(*c) == rank(*sooner) && c.Alias < sooner.Alias)) {
				sooner = c
			}
		}
		if room != nil {
			return urgent(*room, fmt.Sprintf("rule 4: %s at %g%% (%s); %s has most weighted binding headroom", a.Alias, a.binding.Used, a.window, room.Alias))
		}
		if sooner != nil && a.binding.ResetsAt != 0 && sooner.binding.ResetsAt <= a.binding.ResetsAt-escapeMargin {
			return urgent(*sooner, fmt.Sprintf("rule 4: %s binding reset at least %ds before %s", sooner.Alias, escapeMargin, a.Alias))
		}
		d.Reason = "rule 4: no known account below threshold or binding reset at least 300s sooner"
		return d
	}
	if b != nil && a.Windows.SevenDay != nil {
		ar, br := a.Windows.SevenDay.ResetsAt, b.Windows.SevenDay.ResetsAt
		if ar != 0 && br != 0 {
			if br <= ar-tie {
				return switchTo(*b, fmt.Sprintf("rule 3: %s resets %s, at least 1h before %s", b.Alias, time.Unix(br, 0).Local().Format("Mon 15:04"), a.Alias))
			}
			if br > ar-tie && br < ar+tie && rank(*b) < rank(a) {
				return switchTo(*b, fmt.Sprintf("rule 3: %s has higher priority than %s within weekly reset tie", b.Alias, a.Alias))
			}
		}
	}
	d.Reason = "rule 3: below threshold; no eligible account resets 1h sooner or has higher priority within tie"
	return d
}

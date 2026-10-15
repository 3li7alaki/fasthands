package picker

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"fasthands/internal/usage"
)

const timestamp int64 = 1792070000

func account(alias string, used float64, reset int64) Account {
	return Account{ID: "id-" + alias, Alias: alias, Weight: 5, Windows: usage.Windows{
		SevenDay: &usage.Window{Used: used, ResetsAt: reset},
	}}
}

func wantDecision(t *testing.T, list []Account, active string, last int64, target, rule string) Decision {
	t.Helper()
	before, _ := json.Marshal(list)
	d := Decide(list, "id-"+active, last, timestamp)
	after, _ := json.Marshal(list)
	action := "hold"
	if target != "" {
		action, target = "switch", "id-"+target
	}
	if d.Action != action || d.From != "id-"+active || d.To != target || !strings.Contains(d.Reason, rule) || strings.ContainsAny(d.Reason, "\r\n") {
		t.Fatalf("wrong decision: %+v, want %s to %q (%s)", d, action, target, rule)
	}
	if string(before) != string(after) || !reflect.DeepEqual(d, Decide(list, "id-"+active, last, timestamp)) {
		t.Fatal("picker mutated input or produced a nondeterministic decision")
	}
	return d
}

// Slice 5a invariant 1: strict eligibility, relevant models, and missing weekly usage.
func TestEligibility(t *testing.T) {
	for _, tt := range []struct {
		name                string
		weekly, five, model float64
		missing, eligible   bool
	}{
		{"boundary", 80, 0, 0, false, false},
		{"below", 79.99, 0, 0, false, true},
		{"five-boundary", 1, 80, 0, false, false},
		{"five-below", 1, 79.99, 0, false, true},
		{"model-boundary", 1, 1, 80, false, false},
		{"model-below", 1, 1, 79.99, false, true},
		{"unused-model", 0, 0, 0, false, true},
		{"unknown-weekly", 0, 0, 0, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, b := account("a", 40, timestamp+20000), account("b", tt.weekly, timestamp+10000)
			b.Windows.FiveHour = &usage.Window{Used: tt.five}
			b.Windows.Models = map[string]*usage.Window{"used": {Used: tt.model}, "nil": nil}
			if tt.missing {
				b.Windows.SevenDay = nil
			}
			target := ""
			if tt.eligible {
				target = "b"
			}
			wantDecision(t, []Account{a, b}, "a", 0, target, "rule 3")
			if tt.missing {
				for _, used := range []float64{85, 95} {
					a.Windows.SevenDay.Used = 95
					b.Windows.FiveHour = &usage.Window{Used: used, ResetsAt: timestamp + 100}
					wantDecision(t, []Account{a, b}, "a", 0, "", "rule 4")
				}
			}
		})
	}
}

// Slice 5a invariants 2, 3: FEFO anchors ties before priority, weighted headroom, and alias.
func TestEligibleRanking(t *testing.T) {
	for _, mode := range []string{"earliest", "weekly-not-binding", "unknown-last", "all-unknown", "priority", "weight", "alias", "outside-tie", "ranked", "tie-boundary"} {
		t.Run(mode, func(t *testing.T) {
			a := account("a", 92, timestamp+30000)
			b, c := account("b", 50, timestamp+10000), account("c", 10, timestamp+11000)
			want := "c"
			switch mode {
			case "earliest":
				c.Windows.SevenDay.ResetsAt, want = timestamp+20000, "b"
			case "weekly-not-binding":
				b.Windows.FiveHour = &usage.Window{Used: 60, ResetsAt: timestamp + 40000}
				c.Windows.SevenDay.ResetsAt, want = timestamp+20000, "b"
			case "unknown-last":
				b.Windows.SevenDay.ResetsAt = 0
				b.Priority = 1
			case "all-unknown":
				b.Windows.SevenDay.ResetsAt, c.Windows.SevenDay.ResetsAt = 0, 0
				b.Priority, want = 1, "b"
			case "priority":
				b.Priority, c.Priority, want = 1, 2, "b"
			case "weight":
				b.Weight, want = 20, "b"
			case "alias":
				c.Windows.SevenDay.Used, want = 50, "b"
			case "outside-tie":
				c.Windows.SevenDay.ResetsAt, c.Priority, want = timestamp+13601, 1, "b"
			case "ranked":
				b.Priority, want = int(^uint(0)>>1), "b"
			case "tie-boundary":
				c.Windows.SevenDay.ResetsAt, c.Priority = timestamp+13600, 1
			}
			wantDecision(t, []Account{a, b, c}, "a", 0, want, "rule 3")
		})
	}
}

// Slice 5a invariant 4: C is near B but outside A's anchored tie set in all six orders.
func TestNonTransitiveTie(t *testing.T) {
	a := account("active", 92, timestamp+30000)
	others := []Account{account("first", 10, timestamp+10000), account("middle", 50, timestamp+13000), account("last", 1, timestamp+16000)}
	others[0].Priority, others[1].Priority, others[2].Priority = 3, 2, 1
	for _, order := range [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}} {
		wantDecision(t, []Account{a, others[order[0]], others[order[1]], others[order[2]]}, "active", 0, "middle", "rule 3")
	}
}

// Slice 5a invariant 5: sooner reset and priority triggers have distinct, one-way boundaries.
func TestBelowThresholdTriggers(t *testing.T) {
	for _, tt := range []struct {
		name       string
		difference int64
		ap, bp     int
		used       float64
		want       string
	}{
		{"tie-sooner", -3600, 1, 2, 40, "b"},
		{"inside-priority", -3599, 2, 1, 40, "b"},
		{"inside-later", 3599, 2, 1, 40, "b"},
		{"later-boundary", 3600, 2, 1, 40, ""},
		{"priority-one-way", -3599, 1, 2, 40, ""},
		{"hysteresis", 0, 0, 0, 85, ""},
		{"unknown-active-reset", 0, 2, 1, 40, ""},
		{"unknown-target-reset", 0, 2, 1, 40, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, b := account("a", tt.used, timestamp+20000), account("b", 20, timestamp+20000+tt.difference)
			a.Priority, b.Priority = tt.ap, tt.bp
			if tt.name == "unknown-active-reset" {
				a.Windows.SevenDay.ResetsAt = 0
			}
			if tt.name == "unknown-target-reset" {
				b.Windows.SevenDay.ResetsAt = 0
			}
			wantDecision(t, []Account{a, b}, "a", 0, tt.want, "rule 3")
		})
	}
	for _, list := range [][]Account{nil, {account("b", 1, 0)}, {account("a", 99, 0)}} {
		wantDecision(t, list, "a", 0, "", "rule 3")
	}
}

// Slice 5a invariant 6: fallback compares binding headroom, then known binding resets.
func TestThresholdFallback(t *testing.T) {
	for _, mode := range []string{"headroom", "binding-headroom", "weight", "priority", "alias", "margin", "too-close", "unknown-active", "unknown-target", "binding-model", "reset-priority", "threshold"} {
		t.Run(mode, func(t *testing.T) {
			a, b, c := account("a", 92, timestamp+20000), account("b", 85, timestamp+30000), account("c", 88, timestamp+30000)
			want := "b"
			switch mode {
			case "binding-headroom":
				b.Windows.FiveHour, want = &usage.Window{Used: 89}, "c"
			case "weight":
				c.Weight, want = 20, "c"
			case "priority":
				c.Windows.SevenDay.Used, c.Priority, want = 85, 1, "c"
			case "alias":
				c.Windows.SevenDay.Used = 85
			case "threshold":
				a.Windows.SevenDay.Used, b.Windows.SevenDay.Used = 90, 89.99
				c.Windows.SevenDay.Used = 95
			default:
				if mode != "headroom" {
					b.Windows.SevenDay.Used, c.Windows.SevenDay.Used = 94, 95
					a.Windows.FiveHour = &usage.Window{Used: 99, ResetsAt: timestamp + 10000}
					b.Windows.FiveHour = &usage.Window{Used: 99, ResetsAt: timestamp + 9700}
					if mode == "too-close" {
						b.Windows.FiveHour.ResetsAt++
						want = ""
					}
					if mode == "unknown-active" {
						a.Windows.FiveHour.ResetsAt = 0
						want = ""
					}
					if mode == "unknown-target" {
						b.Windows.FiveHour.ResetsAt = 0
						want = ""
					}
					if mode == "binding-model" {
						c.Windows.Models = map[string]*usage.Window{"model": {Used: 99, ResetsAt: timestamp + 9000}}
						want = "c"
					}
					if mode == "reset-priority" {
						c.Windows.FiveHour = &usage.Window{Used: 99, ResetsAt: timestamp + 9700}
						c.Priority, want = 1, "c"
					}
				}
			}
			wantDecision(t, []Account{a, b, c}, "a", 0, want, "rule 4")
		})
	}
}

// Slice 5a invariant 7: cooldown includes second 299, excludes 300, and yields at the limit.
func TestCooldown(t *testing.T) {
	for _, tt := range []struct {
		used    float64
		elapsed int64
		want    string
	}{
		{92, 299, ""}, {92, 300, "b"}, {99.99, 1, ""}, {100, 1, "b"}, {101, 1, "b"},
	} {
		for _, source := range []string{"weekly", "5h", "model"} {
			a, b := account("a", 20, timestamp+20000), account("b", 20, timestamp+10000)
			w := &usage.Window{Used: tt.used, ResetsAt: timestamp + 20000}
			switch source {
			case "weekly":
				a.Windows.SevenDay = w
			case "5h":
				a.Windows.FiveHour = w
			case "model":
				a.Windows.Models = map[string]*usage.Window{"model\nname": w}
			}
			wantDecision(t, []Account{a, b}, "a", timestamp-tt.elapsed, tt.want, "rule 3")
		}
	}
}

func TestEffectiveWindows(t *testing.T) {
	a, b := account("a", 40, timestamp+20000), account("b", 95, timestamp-1)
	b.Windows.Models = map[string]*usage.Window{"expired": {Used: 100, ResetsAt: timestamp - 1}}
	a.Windows.FiveHour = &usage.Window{Used: 100, ResetsAt: timestamp - 1}
	wantDecision(t, []Account{a, b}, "a", 0, "", "rule 3")
	a.Windows.SevenDay.Used = 92
	wantDecision(t, []Account{a, b}, "a", 0, "b", "rule 3")
}

// Slice 5a invariant 8: hourly usage rises only on the active account across staggered weekly resets.
func TestSevenDayNoFlapping(t *testing.T) {
	list := []Account{account("a", 0, timestamp+3*86400), account("b", 0, timestamp+3*86400+14400)}
	active, last, previous, switches := "id-b", int64(0), "", 0
	for hour := int64(0); hour <= 7*24; hour++ {
		at := timestamp + hour*3600
		for i := range list {
			list[i].Windows = usage.Effective(list[i].Windows, at)
			if list[i].ID == active && hour > 0 {
				list[i].Windows.SevenDay.Used += 1.2
			}
		}
		d := Decide(list, active, last, at)
		if d.Action != "switch" {
			continue
		}
		if at-last < 300 || d.To == previous && at-last < 3600 {
			t.Fatalf("flapping at hour %d: %+v", hour, d)
		}
		for _, candidate := range list {
			if candidate.ID == d.To && candidate.Windows.SevenDay.Used >= 80 && !strings.HasPrefix(d.Reason, "rule 4:") {
				t.Fatalf("non-eligible target outside rule 4: %+v", d)
			}
		}
		previous, active, last = active, d.To, at
		switches++
		if next := Decide(list, active, last, at+299); next.Action != "hold" {
			t.Fatalf("second switch inside cooldown: %+v", next)
		}
	}
	if switches < 3 {
		t.Fatal("simulation did not exercise switches across weekly resets")
	}
}

// Usage-forced switches are urgent; reset-chasing switches may wait for idle sessions.
func TestUrgency(t *testing.T) {
	for _, c := range []struct {
		name   string
		list   []Account
		target string
		urgent bool
	}{
		{"threshold", []Account{account("a", 92, timestamp+20000), account("b", 20, timestamp+30000)}, "b", true},
		{"rule 4 band", []Account{account("a", 92, timestamp+20000), account("b", 85, timestamp+30000)}, "b", true},
		{"reset sooner", []Account{account("a", 30, timestamp+20000), account("b", 20, timestamp+10000)}, "b", false},
		{"priority in tie", func() []Account {
			b := account("b", 20, timestamp+20500)
			b.Priority = 1
			return []Account{account("a", 30, timestamp+20000), b}
		}(), "b", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if d := wantDecision(t, c.list, "a", 0, c.target, "rule"); d.Urgent != c.urgent {
				t.Fatalf("urgent = %v, want %v", d.Urgent, c.urgent)
			}
		})
	}
	if d := Decide([]Account{account("a", 30, timestamp+20000), account("b", 20, timestamp+30000)}, "id-a", 0, timestamp); d.Action != "hold" || d.Urgent {
		t.Fatal("a hold is never urgent")
	}
}

package usage

import (
	"slices"
	"time"

	"fasthands/internal/oauth"
)

func (s Store) Reserve(id string, now int64) (ok bool, reason string, err error) {
	err = s.update(func(state *State) {
		a := state.Accounts[id]
		requests := a.Requests[:0]
		for _, at := range a.Requests {
			if at >= now-3600 {
				requests = append(requests, at)
			}
		}
		a.Requests = requests
		switch {
		case now < a.BlockedUntil:
			reason = "blocked until " + time.Unix(a.BlockedUntil, 0).Local().Format("15:04")
		case len(a.Requests) >= 20:
			reason = "request budget spent (20 per hour)"
		default:
			// O3: failed attempts count, so persist before allowing any HTTP request.
			a.Requests = append(a.Requests, now)
			slices.Sort(a.Requests)
			ok = true
		}
		state.Accounts[id] = a
	})
	return ok && err == nil, reason, err
}

func (s Store) Block(id string, until int64) error {
	return s.update(func(state *State) {
		a := state.Accounts[id]
		a.BlockedUntil = max(a.BlockedUntil, until)
		state.Accounts[id] = a
	})
}

func (s Store) SaveFetched(id string, u oauth.Usage, now int64) error {
	return s.update(func(state *State) {
		copyWindow := func(w *oauth.Window) *Window {
			if w == nil {
				return nil
			}
			return &Window{w.Used, w.ResetsAt, now}
		}
		a := state.Accounts[id]
		a.Windows = Windows{FiveHour: copyWindow(u.FiveHour), SevenDay: copyWindow(u.SevenDay)}
		if len(u.Models) != 0 {
			a.Models = make(map[string]*Window, len(u.Models))
			for name, w := range u.Models {
				if w != nil {
					a.Models[name] = copyWindow(w)
				}
			}
		}
		a.Source = "api"
		state.Accounts[id] = a
	})
}

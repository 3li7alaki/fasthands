package accounts

import (
	"fmt"
	"sort"
	"strings"

	"fasthands/internal/picker"
	"fasthands/internal/usage"
)

func (m Manager) SetPriority(aliases []string) error {
	lock, err := m.lock()
	if err != nil {
		return err
	}
	defer unlock(lock)
	db, err := m.read()
	if err != nil {
		return err
	}
	ids := make(map[string]string, len(db.Accounts))
	for id, a := range db.Accounts {
		ids[a.Alias] = id
	}
	ranks := make(map[string]int, len(aliases))
	for i, alias := range aliases {
		if _, ok := ids[alias]; !ok {
			return fmt.Errorf("no account with alias %q", alias)
		}
		if ranks[alias] != 0 {
			return fmt.Errorf("repeated alias %q", alias)
		}
		ranks[alias] = i + 1
	}
	// Picker rule 2: validate the whole order before clearing any saved rank.
	for id, a := range db.Accounts {
		a.Priority = ranks[a.Alias]
		db.Accounts[id] = a
	}
	return m.write(db)
}

func (m Manager) Pickable(state usage.State) ([]picker.Account, error) {
	metadata, err := m.Read()
	if err != nil {
		return nil, err
	}
	list := make([]picker.Account, 0, len(metadata))
	for id, a := range metadata {
		weight := 1.0
		switch {
		case strings.Contains(a.RateLimitTier, "max_20x"):
			weight = 20
		case strings.Contains(a.RateLimitTier, "max_5x"):
			weight = 5
		}
		list = append(list, picker.Account{ID: id, Alias: a.Alias, Windows: state.Accounts[id].Windows, Weight: weight, Priority: a.Priority})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Alias < list[j].Alias })
	return list, nil
}

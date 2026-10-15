package usage

// SaveRefresh records R7/R8 without changing windows, reservations, or other accounts.
func (s Store) SaveRefresh(id, deadRefresh string, retryAt int64) error {
	return s.update(func(state *State) {
		a := state.Accounts[id]
		a.DeadRefresh, a.RefreshRetryAt = deadRefresh, retryAt
		state.Accounts[id] = a
	})
}

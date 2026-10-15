package accounts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"fasthands/internal/claudecfg"
	"fasthands/internal/oauth"
	"fasthands/internal/usage"
)

// R2: inject the race between Fetch's unlocked hint and acquiring accounts.lock.
var beforeRefreshLock = func() {}

type refreshSkip string

func (s refreshSkip) Error() string { return string(s) }

func (m Manager) RefreshIdle(id string, client oauth.Client, loc claudecfg.Locations) ([]byte, error) {
	beforeRefreshLock()
	lock, err := m.lock()
	if err != nil {
		return nil, err
	}
	defer unlock(lock)
	live, err := claudecfg.ActiveUUID(loc)
	if err != nil {
		return nil, err // R1/R2: unknown live identity cannot authorize a refresh.
	}
	if live == id {
		return nil, refreshSkip("access token expired")
	}
	db, err := m.read()
	if err != nil {
		return nil, err
	}
	account, ok := db.Accounts[id]
	if !ok {
		return nil, errors.New("no stored account")
	}
	alias := account.Alias
	blob, err := m.Store.Read(id)
	if err != nil {
		return nil, unreadableBackup(alias)
	}
	token, expires, err := claudecfg.AccessToken(blob)
	if err != nil {
		return nil, unreadableBackup(alias)
	}
	if token != "" && expires > now().Add(60*time.Second).UnixMilli() {
		return blob, nil // R2: another serialized caller may already have refreshed this login.
	}
	_, refresh, err := claudecfg.OAuthTokens(blob)
	if err != nil {
		return nil, unreadableBackup(alias)
	}
	expired := refreshSkip(fmt.Sprintf("stored login expired; log in to Claude Code as %s and run fasthands add", alias))
	if refresh == "" {
		return nil, expired
	}
	digest := sha256.Sum256([]byte(refresh))
	hash := hex.EncodeToString(digest[:8]) // R7: only a lineage fingerprint may enter usage.json.
	store := usage.Store{Directory: m.Paths.State}
	state, err := store.Read()
	if err != nil {
		return nil, err
	}
	if state.Accounts[id].DeadRefresh == hash {
		return nil, expired
	}
	retry := state.Accounts[id].RefreshRetryAt
	if now().Unix() < retry {
		return nil, refreshSkip("token refresh failed; retrying after " + time.Unix(retry, 0).Local().Format("15:04"))
	}
	if m.Store.WritePrev(id, blob) != nil {
		return nil, fmt.Errorf("cannot save previous login for %s", alias) // R3: never send before the recovery copy exists.
	}
	t, err := client.Refresh(context.Background(), refresh)
	if err != nil {
		dead, retry := "", now().Unix()+600 // R8: transient failures wait ten minutes, including invalid_client.
		if errors.Is(err, oauth.ErrInvalidGrant) {
			dead, retry = hash, 0
		}
		if saveErr := store.SaveRefresh(id, dead, retry); saveErr != nil {
			return nil, saveErr
		}
		if dead != "" {
			return nil, expired
		}
		return nil, err
	}
	if (t.AccountUUIDPresent || t.AccountUUID != "") && t.AccountUUID != id {
		return nil, fmt.Errorf("refreshed login for %s belongs to another account; log in to Claude Code as %s and run fasthands add", alias, alias) // R6.
	}
	current, err := m.Store.Read(id)
	if err != nil {
		return nil, fmt.Errorf("cannot check refreshed login for %s; log in to Claude Code as %s and run fasthands add", alias, alias)
	}
	_, currentRefresh, err := claudecfg.OAuthTokens(current)
	if err != nil || currentRefresh != refresh {
		return nil, fmt.Errorf("stored login for %s changed during token refresh; log in to Claude Code as %s and run fasthands add", alias, alias) // R5.
	}
	rotated, err := claudecfg.RotateLogin(blob, t, now().UnixMilli())
	if err != nil {
		return nil, fmt.Errorf("refreshed login for %s could not be composed; log in to Claude Code as %s and run fasthands add", alias, alias)
	}
	// R4: retry only persistence, never the single-use token request.
	if m.Store.Write(id, rotated) != nil && m.Store.Write(id, rotated) != nil {
		return nil, fmt.Errorf("refreshed login for %s could not be saved; log in to Claude Code as %s and run fasthands add", alias, alias)
	}
	if err := store.SaveRefresh(id, "", 0); err != nil {
		return nil, err // R4: the rotated login is durable even if clearing retry state fails.
	}
	return rotated, nil
}

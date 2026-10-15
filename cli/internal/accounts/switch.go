package accounts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"fasthands/internal/claudecfg"
	"fasthands/internal/claudelock"
	"fasthands/internal/claudesessions"
	"fasthands/internal/credstore"
	"fasthands/internal/statehome"
	"fasthands/internal/usage"
)

type SwitchResult struct {
	Switched bool     `json:"switched"`
	From     string   `json:"from"`
	To       string   `json:"to"`
	Store    string   `json:"store"`
	Warnings []string `json:"warnings"`
	Email    string   `json:"-"`
}

type SwitchOptions struct {
	Wait  time.Duration
	Force bool
}

// Local I/O boundaries are injectable for failure and ownership-loss tests (invariants 8, 9).
var claudeLockTimeout = 10 * time.Second
var switchWriteLive = claudecfg.WriteLive
var switchWriteConfig = statehome.ReplaceFile
var beforeSwitchWrite = func(step string) {}
var switchPollInterval = time.Second
var switchScan = claudesessions.Scan

type backupWrite struct {
	blob     []byte
	previous bool
}

func (m Manager) Switch(alias string, loc claudecfg.Locations, platform, securityPath string, options SwitchOptions) (SwitchResult, error) {
	result, err := m.switchAccount(alias, loc, platform, securityPath, options)
	// Take usage.lock only after switchAccount releases Claude's locks and accounts.lock.
	if err == nil && result.Switched {
		if markErr := (usage.Store{Directory: m.Paths.State}).MarkSwitch(now().Unix()); markErr != nil {
			result.Warnings = append(result.Warnings, "cannot record switch time: "+markErr.Error())
		}
	}
	return result, err
}

func (m Manager) switchAccount(alias string, loc claudecfg.Locations, platform, securityPath string, options SwitchOptions) (SwitchResult, error) {
	if !ValidAlias(alias) {
		return SwitchResult{}, errors.New("alias must match ^[a-z0-9][a-z0-9_-]{0,31}$")
	}
	if err := m.waitForSessions(alias, loc, options); err != nil {
		return SwitchResult{}, err
	}
	lock, err := m.lock()
	if err != nil {
		return SwitchResult{}, err
	}
	defer unlock(lock)
	held, err := claudelock.Acquire(claudelock.Locks(loc), claudeLockTimeout)
	if errors.Is(err, claudelock.ErrBusy) {
		return SwitchResult{}, errors.New("Claude Code is busy with its credentials; retry in a few seconds")
	}
	if err != nil {
		return SwitchResult{}, err
	}
	defer held.Release()

	db, err := m.read()
	if err != nil {
		return SwitchResult{}, err
	}
	var targetID string
	var target Account
	for id, account := range db.Accounts {
		if account.Alias == alias {
			targetID, target = id, account
			break
		}
	}
	if targetID == "" {
		return SwitchResult{}, fmt.Errorf("no account with alias %q", alias)
	}
	live, inKeychain, err := claudecfg.ReadLive(loc, platform, securityPath)
	if err != nil {
		return SwitchResult{}, err
	}
	data, err := os.ReadFile(loc.GlobalConfig)
	if err != nil {
		return SwitchResult{}, fmt.Errorf("cannot read global config at %q", loc.GlobalConfig)
	}
	var config, identity map[string]json.RawMessage
	if json.Unmarshal(data, &config) != nil || config == nil {
		return SwitchResult{}, fmt.Errorf("invalid global config at %q", loc.GlobalConfig)
	}
	if json.Unmarshal(config["oauthAccount"], &identity) != nil || identity == nil {
		return SwitchResult{}, errors.New("no active Claude Code login")
	}
	var liveID, email string
	if json.Unmarshal(identity["accountUuid"], &liveID) != nil || liveID == "" {
		return SwitchResult{}, errors.New("no active Claude Code login")
	}
	json.Unmarshal(identity["emailAddress"], &email)
	active, managed := db.Accounts[liveID]
	result := SwitchResult{From: active.Alias, To: alias, Store: "file", Warnings: []string{}, Email: target.Email}
	if inKeychain {
		result.Store = "keychain"
	}
	if liveID == targetID {
		return result, nil
	}
	sessions, err := switchScan(loc.ConfigHome)
	if err != nil {
		return SwitchResult{}, err
	}
	if mid := othersMidTurn(sessions); len(mid) != 0 {
		message := midTurnMessage(mid)
		if !options.Force {
			return SwitchResult{}, errors.New(message + "; retry when they finish, or pass --wait or --force")
		}
		result.Warnings = append(result.Warnings, message)
	}
	if !managed {
		return SwitchResult{}, fmt.Errorf("the active Claude Code login (%s) is not managed by fasthands; run fasthands add first", email)
	}
	writes, warnings, err := m.outgoing(db, liveID, live)
	if err != nil {
		return SwitchResult{}, err
	}
	result.Warnings = append(result.Warnings, warnings...)
	targetBlob, err := m.Store.Read(targetID)
	if errors.Is(err, credstore.ErrAbsent) {
		return SwitchResult{}, fmt.Errorf("no stored login for %s; log in as it and run fasthands add", alias)
	}
	if err != nil {
		return SwitchResult{}, unreadableBackup(alias)
	}
	_, refresh, err := claudecfg.OAuthTokens(targetBlob)
	if err != nil || refresh == "" {
		return SwitchResult{}, fmt.Errorf("stored login for %s is not a Claude OAuth login with a refresh token", alias)
	}
	composed, err := claudecfg.MergeCredentials(targetBlob, live)
	if err != nil {
		return SwitchResult{}, errors.New("cannot compose Claude Code login")
	}
	var targetIdentity map[string]json.RawMessage
	var identityID string
	if json.Unmarshal(target.OAuthAccount, &targetIdentity) != nil || targetIdentity == nil ||
		json.Unmarshal(targetIdentity["accountUuid"], &identityID) != nil || identityID != targetID {
		return SwitchResult{}, fmt.Errorf("invalid stored oauthAccount for %s", alias)
	}
	// F3: RawMessage keeps unrelated values and numeric precision out of Go conversions.
	config["oauthAccount"] = target.OAuthAccount
	var encodedConfig bytes.Buffer
	encoder := json.NewEncoder(&encodedConfig)
	encoder.SetIndent("", "  ")
	// F3: JSON.stringify does not HTML-escape unrelated string values.
	encoder.SetEscapeHTML(false)
	if encoder.Encode(config) != nil {
		return SwitchResult{}, fmt.Errorf("cannot encode global config at %q", loc.GlobalConfig)
	}
	newConfig := encodedConfig.Bytes()
	if platform == "darwin" {
		for _, write := range writes {
			if err := credstore.CheckBackup(liveID, write.blob, write.previous); err != nil {
				return SwitchResult{}, err
			}
		}
	}

	liveWritten := false
	rollback := func() error {
		if switchWriteLive(loc, platform, securityPath, inKeychain, live) != nil {
			return fmt.Errorf("switch failed and the rollback failed: run fasthands switch %s to recover", active.Alias)
		}
		return errors.New("switch failed and was rolled back")
	}
	check := func(step string) error {
		beforeSwitchWrite(step)
		if err := held.Lost(); err != nil {
			if liveWritten {
				return rollback()
			}
			return errors.New("lost Claude Code credential lock; retry in a few seconds")
		}
		return nil
	}
	for _, write := range writes {
		step := "backup"
		if write.previous {
			step = "previous"
		}
		if err := check(step); err != nil {
			return SwitchResult{}, err
		}
		if write.previous {
			err = m.Store.WritePrev(liveID, write.blob)
		} else {
			err = m.Store.Write(liveID, write.blob)
		}
		if err != nil {
			return SwitchResult{}, err
		}
		if !write.previous {
			subscription, tier := claudecfg.Plan(write.blob)
			if active.SubscriptionType != subscription || active.RateLimitTier != tier {
				active.SubscriptionType, active.RateLimitTier = subscription, tier
				db.Accounts[liveID] = active
				// Save U4 metadata only when the outgoing backup actually accepts this login.
				if err := m.write(db); err != nil {
					return SwitchResult{}, err
				}
			}
		}
	}
	if err := check("live"); err != nil {
		return SwitchResult{}, err
	}
	if err := switchWriteLive(loc, platform, securityPath, inKeychain, composed); err != nil {
		return SwitchResult{}, fmt.Errorf("cannot write active Claude Code login for %s", alias)
	}
	liveWritten = true
	if err := check("config"); err != nil {
		return SwitchResult{}, err
	}
	if switchWriteConfig(loc.GlobalConfig, newConfig) != nil {
		return SwitchResult{}, rollback()
	}
	result.Switched = true
	return result, nil
}

func (m Manager) waitForSessions(alias string, loc claudecfg.Locations, options SwitchOptions) error {
	db, err := m.read()
	if err != nil {
		return err
	}
	// S3: an unlocked hint skips waiting only; the locked identity check still decides.
	data, _ := os.ReadFile(loc.GlobalConfig)
	var config, identity map[string]json.RawMessage
	var liveID string
	if json.Unmarshal(data, &config) == nil && json.Unmarshal(config["oauthAccount"], &identity) == nil {
		json.Unmarshal(identity["accountUuid"], &liveID)
	}
	for id, account := range db.Accounts {
		if account.Alias == alias && id == liveID {
			return nil
		}
	}
	if options.Force {
		return nil
	}
	deadline := time.Now().Add(options.Wait)
	for {
		sessions, err := switchScan(loc.ConfigHome)
		if err != nil {
			return err
		}
		if len(othersMidTurn(sessions)) == 0 || time.Until(deadline) <= 0 {
			return nil
		}
		// S3: waiting holds neither the accounts flock nor Claude's credential locks.
		time.Sleep(min(switchPollInterval, time.Until(deadline)))
	}
}

// othersMidTurn drops the Claude session that is running this command (`!` or a tool
// call): it is busy by definition and asked for the switch. Claude Code sets CLAUDE_PID
// in every child process (observed on 2.1.300).
func othersMidTurn(sessions []claudesessions.Session) []claudesessions.Session {
	mid := claudesessions.MidTurn(sessions)
	caller, err := strconv.Atoi(os.Getenv("CLAUDE_PID"))
	if err != nil || caller <= 1 {
		return mid
	}
	others := mid[:0]
	for _, session := range mid {
		if session.Unreadable || session.PID != caller {
			others = append(others, session)
		}
	}
	return others
}

func midTurnMessage(sessions []claudesessions.Session) string {
	var names []string
	for _, session := range sessions {
		if session.Unreadable {
			names = append(names, "unreadable record "+session.Path)
		} else {
			names = append(names, fmt.Sprintf("pid %d (cwd %s)", session.PID, session.CWD))
		}
	}
	return fmt.Sprintf("%d Claude session(s) mid-turn: %s", len(sessions), strings.Join(names, ", "))
}

func unreadableBackup(alias string) error {
	return fmt.Errorf("stored login for %s is unreadable right now; retry, do not re-add", alias)
}

func (m Manager) outgoing(db database, id string, live []byte) ([]backupWrite, []string, error) {
	active := db.Accounts[id]
	access, refresh, err := claudecfg.OAuthTokens(live)
	if err != nil {
		return nil, nil, errors.New("active login is not a Claude OAuth login")
	}
	if access == "" && refresh == "" {
		// F5: a rejected refresh empties tokens in place; never burn the stored grant.
		return nil, []string{fmt.Sprintf("the active login's tokens were wiped by Claude Code; kept %s's stored backup", active.Alias)}, nil
	}
	owned, err := claudecfg.OwnedCredentials(live)
	if err != nil {
		return nil, nil, errors.New("active login is not a Claude OAuth login")
	}
	stored, err := m.Store.Read(id)
	if err != nil && !errors.Is(err, credstore.ErrAbsent) {
		return nil, nil, unreadableBackup(active.Alias)
	}
	if bytes.Equal(owned, stored) {
		return nil, nil, nil
	}
	var storedRefresh string
	if stored != nil {
		_, storedRefresh, err = claudecfg.OAuthTokens(stored)
		if err != nil {
			return nil, nil, unreadableBackup(active.Alias)
		}
	}
	if refresh != "" && refresh != storedRefresh {
		// F6: equal refresh tokens prove lineage offline; other rotations remain unproven.
		ids := make([]string, 0, len(db.Accounts))
		for other := range db.Accounts {
			if other != id {
				ids = append(ids, other)
			}
		}
		sort.Strings(ids)
		for _, other := range ids {
			blob, err := m.Store.Read(other)
			if errors.Is(err, credstore.ErrAbsent) {
				continue
			}
			if err != nil {
				return nil, nil, unreadableBackup(db.Accounts[other].Alias)
			}
			_, otherRefresh, err := claudecfg.OAuthTokens(blob)
			if err == nil && refresh == otherRefresh {
				return nil, []string{fmt.Sprintf("the active login matches %s's stored login; not saved into %s", db.Accounts[other].Alias, active.Alias)}, nil
			}
		}
	}
	var writes []backupWrite
	if stored != nil {
		writes = append(writes, backupWrite{stored, true})
	}
	return append(writes, backupWrite{owned, false}), nil, nil
}

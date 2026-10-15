// Package accounts manages account metadata and serializes backup updates.
package accounts

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"fasthands/internal/claudecfg"
	"fasthands/internal/credstore"
	"fasthands/internal/statehome"
)

type Account struct {
	Alias            string          `json:"alias"`
	Email            string          `json:"email"`
	OrganizationUUID string          `json:"organizationUuid"`
	AddedAt          string          `json:"addedAt"`
	UpdatedAt        string          `json:"updatedAt"`
	Store            string          `json:"store"`
	OAuthAccount     json.RawMessage `json:"oauthAccount"`
}

type database struct {
	SchemaVersion int                `json:"schemaVersion"`
	Accounts      map[string]Account `json:"accounts"`
}

type Result struct {
	Alias            string `json:"alias"`
	AccountUUID      string `json:"accountUuid"`
	Email            string `json:"email"`
	OrganizationUUID string `json:"organizationUuid"`
	Store            string `json:"store"`
	Updated          bool   `json:"updated"`
}

type Listed struct {
	Alias       string `json:"alias"`
	Email       string `json:"email"`
	AccountUUID string `json:"accountUuid"`
	AddedAt     string `json:"addedAt"`
	Store       string `json:"store"`
}

type Manager struct {
	Paths statehome.Paths
	Store credstore.Backend
}

var aliasPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

func ValidAlias(alias string) bool { return aliasPattern.MatchString(alias) }

func (m Manager) read() (database, error) {
	path := filepath.Join(m.Paths.State, "accounts.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return database{SchemaVersion: 1, Accounts: make(map[string]Account)}, nil
	}
	if err != nil {
		return database{}, fmt.Errorf("cannot read accounts at %q", path)
	}
	var db database
	if json.Unmarshal(data, &db) != nil || db.SchemaVersion != 1 || db.Accounts == nil {
		return database{}, fmt.Errorf("invalid accounts metadata at %q", path)
	}
	return db, nil
}

func (m Manager) Add(c claudecfg.Capture, alias string, aliasGiven bool) (Result, error) {
	if !credstore.ValidAccount(c.AccountUUID) {
		return Result{}, errors.New("invalid accountUuid for credential storage")
	}
	if aliasGiven && !ValidAlias(alias) {
		return Result{}, errors.New("alias must match ^[a-z0-9][a-z0-9_-]{0,31}$")
	}
	if err := statehome.PrivateDir(m.Paths.State); err != nil {
		return Result{}, fmt.Errorf("cannot create state directory %q", m.Paths.State)
	}
	lockPath := filepath.Join(m.Paths.State, "accounts.lock")
	// Keep one stable inode across atomic metadata renames and across processes.
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return Result{}, fmt.Errorf("cannot open accounts lock at %q", lockPath)
	}
	defer lock.Close()
	if err := lock.Chmod(0600); err != nil {
		return Result{}, fmt.Errorf("cannot secure accounts lock at %q", lockPath)
	}
	for {
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		return Result{}, fmt.Errorf("cannot acquire accounts lock at %q", lockPath)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	db, err := m.read()
	if err != nil {
		return Result{}, err
	}
	previous, updated := db.Accounts[c.AccountUUID]
	if !aliasGiven {
		alias = previous.Alias
		if !updated {
			alias = defaultAlias(c.Email, c.AccountUUID, db.Accounts)
		}
	}
	for id, account := range db.Accounts {
		if id != c.AccountUUID && account.Alias == alias {
			return Result{}, fmt.Errorf("alias %q is already in use", alias)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	added := previous.AddedAt
	if !updated {
		added = now
	}
	db.Accounts[c.AccountUUID] = Account{alias, c.Email, c.OrganizationUUID, added, now, m.Store.Kind(), c.OAuthAccount}
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return Result{}, errors.New("cannot encode accounts metadata")
	}
	if err := m.Store.Write(c.AccountUUID, c.Credentials); err != nil {
		return Result{}, err
	}
	path := filepath.Join(m.Paths.State, "accounts.json")
	if err := statehome.AtomicWrite(path, append(data, '\n')); err != nil {
		return Result{}, fmt.Errorf("cannot write accounts at %q", path)
	}
	return Result{alias, c.AccountUUID, c.Email, c.OrganizationUUID, m.Store.Kind(), updated}, nil
}

func defaultAlias(email, id string, accounts map[string]Account) string {
	local, _, _ := strings.Cut(strings.ToLower(email), "@")
	var clean strings.Builder
	for _, c := range local {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' {
			clean.WriteRune(c)
		} else {
			clean.WriteByte('-')
		}
	}
	base := strings.Trim(clean.String(), "-_")
	if base == "" {
		base = "account"
	}
	if len(base) > 32 {
		base = base[:32]
	}
	for n := 1; ; n++ {
		alias := base
		if n > 1 {
			suffix := "-" + strconv.Itoa(n)
			limit := min(len(base), 32-len(suffix))
			alias = base[:limit] + suffix
		}
		used := false
		for other, account := range accounts {
			if other != id && account.Alias == alias {
				used = true
				break
			}
		}
		if !used {
			return alias
		}
	}
}

func (m Manager) List() ([]Listed, error) {
	db, err := m.read()
	if err != nil {
		return nil, err
	}
	list := make([]Listed, 0, len(db.Accounts))
	for id, account := range db.Accounts {
		list = append(list, Listed{account.Alias, account.Email, id, account.AddedAt, account.Store})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Alias < list[j].Alias })
	return list, nil
}

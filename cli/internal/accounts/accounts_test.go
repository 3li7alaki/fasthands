package accounts

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"fasthands/internal/claudecfg"
	"fasthands/internal/credstore"
	"fasthands/internal/statehome"
)

func manager(root string) Manager {
	paths := statehome.Paths{State: filepath.Join(root, "state"), Credentials: filepath.Join(root, "credentials")}
	return Manager{Paths: paths, Store: credstore.Files{Directory: paths.Credentials}}
}

func capture(id, email string) claudecfg.Capture {
	account, _ := json.Marshal(map[string]any{
		"accountUuid": id, "emailAddress": email, "organizationUuid": "org", "future": map[string]bool{"keep": true},
	})
	return claudecfg.Capture{
		AccountUUID: id, Email: email, OrganizationUUID: "org", OAuthAccount: account,
		Credentials: []byte(`{"claudeAiOauth":{"accessToken":"account-access-private","refreshToken":"account-refresh-private"}}`),
	}
}

func TestAddRefreshAndAlias(t *testing.T) {
	m := manager(t.TempDir())
	first, err := m.Add(capture("id-one", "Person@example.com"), "", false)
	if err != nil || first.Alias != "person" || first.Updated || first.Store != "file" {
		t.Fatal("initial account add failed")
	}
	second, err := m.Add(capture("id-two", "Person@other.com"), "", false)
	if err != nil || second.Alias != "person-2" {
		t.Fatal("default alias collision not resolved")
	}
	third, err := m.Add(capture("id-three", "Person@third.com"), "", false)
	if err != nil || third.Alias != "person-3" {
		t.Fatal("default alias suffix did not advance")
	}
	db, err := m.read()
	if err != nil || db.SchemaVersion != 1 || len(db.Accounts) != 3 {
		t.Fatal("wrong metadata schema")
	}
	original := db.Accounts["id-one"]
	for _, value := range []string{original.AddedAt, original.UpdatedAt} {
		parsed, parseErr := time.Parse(time.RFC3339, value)
		if parseErr != nil || !strings.HasSuffix(value, "Z") || parsed.Location() != time.UTC {
			t.Fatal("timestamps must use RFC3339 UTC")
		}
	}
	refresh := capture("id-one", "New@example.com")
	refresh.OrganizationUUID = "new-org"
	refresh.OAuthAccount = json.RawMessage(`{"accountUuid":"id-one","emailAddress":"New@example.com","organizationUuid":"new-org","future":{"keep":false}}`)
	refresh.Credentials = []byte(`{"claudeAiOauth":{"accessToken":"new-access-private","refreshToken":"new-refresh-private"}}`)
	updated, err := m.Add(refresh, "", false)
	if err != nil || !updated.Updated || updated.Alias != "person" || updated.Email != refresh.Email || updated.OrganizationUUID != refresh.OrganizationUUID {
		t.Fatal("refresh must keep alias and update identity")
	}
	db, err = m.read()
	stored := db.Accounts["id-one"]
	var got, want any
	if err != nil || stored.AddedAt != original.AddedAt || json.Unmarshal(stored.OAuthAccount, &got) != nil || json.Unmarshal(refresh.OAuthAccount, &want) != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("refresh lost original addedAt or full oauthAccount")
	}
	backup, err := os.ReadFile(filepath.Join(m.Paths.Credentials, "id-one.json"))
	if err != nil || string(backup) != string(refresh.Credentials) {
		t.Fatal("refresh did not replace backup")
	}
	metadata, err := os.ReadFile(filepath.Join(m.Paths.State, "accounts.json"))
	if err != nil || strings.Contains(string(metadata), "private") || strings.Contains(string(metadata), "claudeAiOauth") {
		t.Fatal("credential found in metadata")
	}
	renamed, err := m.Add(refresh, "work", true)
	if err != nil || renamed.Alias != "work" || !renamed.Updated {
		t.Fatal("explicit alias must replace saved alias")
	}
	list, err := m.List()
	if err != nil || len(list) != 3 || list[0].Alias != "person-2" || list[2].Alias != "work" {
		t.Fatal("list must sort accounts by alias")
	}
}

func TestAliasValidationAndDefaulting(t *testing.T) {
	for _, alias := range []string{"a", "0", "a_b-c", strings.Repeat("a", 32)} {
		if !ValidAlias(alias) {
			t.Fatalf("valid alias rejected: %q", alias)
		}
	}
	for _, alias := range []string{"", "_a", "-a", "A", "a b", "a.b", "a\n", strings.Repeat("a", 33)} {
		if ValidAlias(alias) {
			t.Fatalf("invalid alias accepted: %q", alias)
		}
	}
	for _, tt := range []struct{ email, want string }{
		{"UPPER@example.com", "upper"}, {"First.Last+tag@example.com", "first-last-tag"}, {"", "account"},
		{"___@example.com", "account"}, {strings.Repeat("a", 40) + "@example.com", strings.Repeat("a", 32)},
	} {
		got := defaultAlias(tt.email, "id", nil)
		if got != tt.want || !ValidAlias(got) {
			t.Fatal("invalid default alias")
		}
	}
	long := strings.Repeat("a", 32)
	got := defaultAlias(long+"@example.com", "id", map[string]Account{"other": {Alias: long}})
	if got != strings.Repeat("a", 30)+"-2" {
		t.Fatal("collision suffix must fit alias limit")
	}
}

func TestAliasCollisionAndBadMetadataPreserveBackup(t *testing.T) {
	m := manager(t.TempDir())
	if _, err := m.Add(capture("id-one", "one@example.com"), "work", true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(m.Paths.State, "accounts.json")
	before, _ := os.ReadFile(path)
	if _, err := m.Add(capture("id-two", "two@example.com"), "work", true); err == nil {
		t.Fatal("explicit alias collision must fail")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("alias collision changed metadata")
	}
	if _, err := os.Stat(filepath.Join(m.Paths.Credentials, "id-two.json")); !os.IsNotExist(err) {
		t.Fatal("alias collision wrote backup")
	}
	backupPath := filepath.Join(m.Paths.Credentials, "id-one.json")
	backup, _ := os.ReadFile(backupPath)
	for _, invalid := range []string{`null`, `{}`, `{"schemaVersion":2,"accounts":{}}`, `{"schemaVersion":1,"accounts":null}`, `malformed-private`} {
		if err := os.WriteFile(path, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Add(capture("id-one", "one@example.com"), "", false); err == nil || strings.Contains(err.Error(), "malformed-private") {
			t.Fatal("invalid metadata must fail without quoting content")
		}
		after, _ := os.ReadFile(backupPath)
		if string(backup) != string(after) {
			t.Fatal("bad metadata changed backup")
		}
	}
}

func TestStorageModesUnderPermissiveUmask(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	root := filepath.Join(t.TempDir(), "new-home")
	m := manager(root)
	if _, err := m.Add(capture("id", "one@example.com"), "", false); err != nil {
		t.Fatal(err)
	}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		want := os.FileMode(0600)
		if info.IsDir() {
			want = 0700
		}
		if info.Mode().Perm() != want {
			t.Errorf("wrong mode for %s: %o", path, info.Mode().Perm())
		}
		if strings.HasSuffix(path, ".tmp") {
			t.Error("temporary file left behind")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestListEmpty(t *testing.T) {
	m := manager(filepath.Join(t.TempDir(), "absent"))
	list, err := m.List()
	if err != nil || list == nil || len(list) != 0 {
		t.Fatal("empty store must return non-nil empty list")
	}
	if _, err := os.Stat(m.Paths.State); !os.IsNotExist(err) {
		t.Fatal("listing absent store must not create state")
	}
}

func TestAccountProcess(t *testing.T) {
	if os.Getenv("FH_ACCOUNT_WORKER") != "1" {
		return
	}
	id := os.Getenv("FH_ACCOUNT_ID")
	if err := os.WriteFile(filepath.Join(os.Getenv("FH_ACCOUNT_ROOT"), id+".ready"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager(os.Getenv("FH_ACCOUNT_ROOT")).Add(capture(id, "same@example.com"), "", false); err != nil {
		t.Fatal(err)
	}
}

func TestFlockSerializesProcesses(t *testing.T) {
	root := t.TempDir()
	m := manager(root)
	if err := statehome.PrivateDir(m.Paths.State); err != nil {
		t.Fatal(err)
	}
	lock, err := os.OpenFile(filepath.Join(m.Paths.State, "accounts.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	const count = 8
	done := make(chan error, count)
	for i := 0; i < count; i++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestAccountProcess$")
		cmd.Env = append(os.Environ(), "FH_ACCOUNT_WORKER=1", "FH_ACCOUNT_ROOT="+root, fmt.Sprintf("FH_ACCOUNT_ID=id-%d", i))
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill() })
		go func() { done <- cmd.Wait() }()
	}
	deadline := time.Now().Add(10 * time.Second)
	for i := 0; i < count; i++ {
		for {
			_, err := os.Stat(filepath.Join(root, fmt.Sprintf("id-%d.ready", i)))
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("worker did not reach lock boundary")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	select {
	case <-done:
		t.Fatal("account writer bypassed held process lock")
	case <-time.After(100 * time.Millisecond):
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < count; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal("account worker failed")
			}
		case <-time.After(time.Until(deadline)):
			t.Fatal("account worker timed out")
		}
	}
	list, err := m.List()
	if err != nil || len(list) != count {
		t.Fatal("concurrent updates lost accounts")
	}
	aliases := map[string]bool{}
	for _, account := range list {
		if aliases[account.Alias] {
			t.Fatal("concurrent updates duplicated aliases")
		}
		aliases[account.Alias] = true
		if _, err := os.Stat(filepath.Join(m.Paths.Credentials, account.AccountUUID+".json")); err != nil {
			t.Fatal("concurrent update lost backup")
		}
	}
}

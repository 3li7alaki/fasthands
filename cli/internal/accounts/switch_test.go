package accounts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"fasthands/internal/claudecfg"
	"fasthands/internal/claudelock"
	"fasthands/internal/credstore"
)

const oldLogin = `{"claudeAiOauth":{"accessToken":"old-access-private","refreshToken":"old-refresh-private"}}`
const liveLogin = " {\n\"claudeAiOauth\":{\"accessToken\":\"live-access-private\",\"refreshToken\":\"live-refresh-private\"},\"mcpOAuth\":{\"live\":true},\"pluginSecrets\":{\"secret\":\"machine-private\"},\"mcpOAuthClientConfig\":{},\"mcpXaaIdpConfig\":null,\"trustedDeviceToken\":\"a-device-private\",\"onlyA\":true}\n"
const targetLogin = `{"claudeAiOauth":{"accessToken":"target-access-private","refreshToken":"target-refresh-private"},"mcpOAuth":{"stale":true},"mcpXaaIdp":{"stale":true},"trustedDeviceToken":"b-device-private","unknown":{"keep":[1,true]}}`
const globalConfig = `{"oauthAccount":{"accountUuid":"id-a","emailAddress":"a@example.com"},"large":9007199254740993,"other":{"keep":[1,true,"<unchanged>"]},"precise":1.2300e+4}`

type switchFixture struct {
	m                    Manager
	loc                  claudecfg.Locations
	platform, security   string
	keychain             string
	live, stored, target []byte
}

func setupSwitch(t *testing.T, platform string) *switchFixture {
	t.Helper()
	root := t.TempDir()
	config, storage := filepath.Join(root, "config"), filepath.Join(root, "storage")
	for _, dir := range []string{config, storage} {
		if err := os.Mkdir(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", root)
	t.Setenv("USER", "test-user")
	t.Setenv("CLAUDE_CONFIG_DIR", config)
	t.Setenv("CLAUDE_SECURESTORAGE_CONFIG_DIR", storage)
	t.Setenv("FASTHANDS_HOME", filepath.Join(root, "fasthands"))
	f := &switchFixture{m: manager(filepath.Join(root, "fasthands")), platform: platform,
		live: []byte(liveLogin), stored: []byte(oldLogin), target: []byte(targetLogin)}
	put(t, filepath.Join(config, ".config.json"), []byte(globalConfig))
	var err error
	f.loc, err = claudecfg.Locate()
	if err != nil {
		t.Fatal(err)
	}
	if platform == "darwin" {
		f.keychain = filepath.Join(root, "keychain")
		if err := os.Mkdir(f.keychain, 0700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("FH_KEYCHAIN", f.keychain)
		t.Setenv("FH_FAIL_READ", "")
		t.Setenv("FH_FAIL_WRITE", "")
		put(t, filepath.Join(f.keychain, "error"), []byte(liveLogin))
		script, err := os.ReadFile("../credstore/testdata/security")
		if err != nil {
			t.Fatal(err)
		}
		f.security = filepath.Join(root, "security")
		put(t, f.security, script)
		if err := os.Chmod(f.security, 0700); err != nil {
			t.Fatal(err)
		}
		f.m.Store = credstore.Keychain{SecurityPath: f.security}
	}
	for _, entry := range []struct {
		id, alias string
		blob      []byte
	}{{"id-a", "a", f.stored}, {"id-b", "b", f.target}} {
		c := capture(entry.id, entry.alias+"@example.com")
		c.Credentials = entry.blob
		if _, err := f.m.Add(c, entry.alias, true); err != nil {
			t.Fatal(err)
		}
	}
	f.setLive(t, f.live)
	oldTimeout, oldLive, oldConfig, oldHook := claudeLockTimeout, switchWriteLive, switchWriteConfig, beforeSwitchWrite
	claudeLockTimeout = 10 * time.Millisecond
	t.Cleanup(func() {
		claudeLockTimeout, switchWriteLive, switchWriteConfig, beforeSwitchWrite = oldTimeout, oldLive, oldConfig, oldHook
	})
	if platform == "darwin" {
		put(t, filepath.Join(f.keychain, "calls"), nil)
		put(t, filepath.Join(f.keychain, "writes"), nil)
	}
	return f
}

func put(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func (f *switchFixture) setLive(t *testing.T, blob []byte) {
	t.Helper()
	if f.platform == "darwin" {
		f.setItem(t, f.loc.Service, f.loc.KeychainAccount, blob)
	} else {
		put(t, f.loc.CredentialsFile, blob)
	}
}

func (f *switchFixture) setItem(t *testing.T, service, account string, blob []byte) {
	t.Helper()
	dir := filepath.Join(f.keychain, service)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(dir, account), []byte(hex.EncodeToString(blob)))
}

func (f *switchFixture) backupPath(id string, previous bool) string {
	if f.platform == "darwin" {
		service := "fasthands"
		if previous {
			service = "fasthands-prev"
		}
		return filepath.Join(f.keychain, service, id)
	}
	suffix := ".json"
	if previous {
		suffix = ".prev.json"
	}
	return filepath.Join(f.m.Paths.Credentials, id+suffix)
}

func (f *switchFixture) rawBackup(t *testing.T, id string, previous bool) []byte {
	t.Helper()
	blob, err := os.ReadFile(f.backupPath(id, previous))
	if err != nil {
		t.Fatal(err)
	}
	if f.platform == "darwin" {
		blob, err = hex.DecodeString(string(blob))
		if err != nil {
			t.Fatal("fake Keychain item is not hex")
		}
	}
	return blob
}

func (f *switchFixture) rawLive(t *testing.T) []byte {
	t.Helper()
	path := f.loc.CredentialsFile
	if f.platform == "darwin" {
		path = filepath.Join(f.keychain, f.loc.Service, f.loc.KeychainAccount)
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.platform == "darwin" {
		blob, err = hex.DecodeString(string(blob))
		if err != nil {
			t.Fatal("fake live item is not hex")
		}
	}
	return blob
}

type switchSnapshot struct {
	Mode os.FileMode
	Time int64
	Hash [32]byte
}

func (f *switchFixture) snapshot(t *testing.T) map[string]switchSnapshot {
	t.Helper()
	paths := []string{f.loc.CredentialsFile, f.loc.GlobalConfig, f.m.Paths.State, f.m.Paths.Credentials}
	if f.platform == "darwin" {
		paths = append(paths, filepath.Join(f.keychain, f.loc.Service), filepath.Join(f.keychain, "fasthands"), filepath.Join(f.keychain, "fasthands-prev"))
	}
	result := map[string]switchSnapshot{}
	for _, root := range paths {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			result[path] = switchSnapshot{info.Mode(), info.ModTime().UnixNano(), sha256.Sum256(data)}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func noSwitchSecrets(t *testing.T, output string) {
	t.Helper()
	for _, token := range []string{"live-access-private", "live-refresh-private", "target-access-private", "target-refresh-private", "machine-private", "old-refresh-private", "injected-private"} {
		if strings.Contains(output, token) || strings.Contains(strings.ToLower(output), hex.EncodeToString([]byte(token))) {
			t.Fatal("credential escaped into switch output")
		}
	}
}

// Invariants 1, 2, 14: rotation saves both outgoing generations and merges only machine keys.
func TestSwitchHappyPath(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			f := setupSwitch(t, platform)
			metadata, _ := os.ReadFile(filepath.Join(f.m.Paths.State, "accounts.json"))
			var steps []string
			beforeSwitchWrite = func(step string) { steps = append(steps, step) }
			result, err := f.m.Switch("b", f.loc, platform, f.security, SwitchOptions{})
			if err != nil || !result.Switched || result.From != "a" || result.To != "b" || result.Store != f.m.Store.Kind() || result.Warnings == nil || len(result.Warnings) != 0 {
				t.Fatalf("switch failed: %v", err)
			}
			if !reflect.DeepEqual(steps, []string{"previous", "backup", "live", "config"}) {
				t.Fatal("writes occurred out of order")
			}
			var live map[string]json.RawMessage
			if json.Unmarshal(f.rawLive(t), &live) != nil || len(live) != 7 || string(live["mcpOAuth"]) != `{"live":true}` || string(live["pluginSecrets"]) != `{"secret":"machine-private"}` || string(live["mcpOAuthClientConfig"]) != `{}` || string(live["mcpXaaIdpConfig"]) != `null` || live["mcpXaaIdp"] != nil || live["onlyA"] != nil || string(live["trustedDeviceToken"]) != `"b-device-private"` || string(live["unknown"]) != `{"keep":[1,true]}` {
				t.Fatal("activation lost target keys or used stale machine keys")
			}
			if _, refresh, err := claudecfg.OAuthTokens(f.rawLive(t)); err != nil || refresh != "target-refresh-private" {
				t.Fatal("target login was not activated")
			}
			owned, _ := claudecfg.OwnedCredentials(f.live)
			if !bytes.Equal(f.rawBackup(t, "id-a", false), owned) || !bytes.Equal(f.rawBackup(t, "id-a", true), f.stored) || !bytes.Equal(f.rawBackup(t, "id-b", false), f.target) {
				t.Fatal("outgoing backup generations or target backup changed incorrectly")
			}
			config, readErr := os.ReadFile(f.loc.GlobalConfig)
			var got, old map[string]json.RawMessage
			if readErr != nil || json.Unmarshal(config, &got) != nil || json.Unmarshal([]byte(globalConfig), &old) != nil {
				t.Fatal("invalid global config after switch")
			}
			db, _ := f.m.read()
			var expectedIdentity, actualIdentity any
			json.Unmarshal(db.Accounts["id-b"].OAuthAccount, &expectedIdentity)
			json.Unmarshal(got["oauthAccount"], &actualIdentity)
			if !reflect.DeepEqual(actualIdentity, expectedIdentity) || !bytes.HasSuffix(config, []byte("\n")) || !bytes.Contains(config, []byte("\n  \"oauthAccount\"")) {
				t.Fatal("global identity or formatting differs from contract")
			}
			for _, key := range []string{"large", "other", "precise"} {
				var compact bytes.Buffer
				if json.Compact(&compact, got[key]) != nil || compact.String() != string(old[key]) {
					t.Fatal("unrelated config value changed")
				}
			}
			after, _ := os.ReadFile(filepath.Join(f.m.Paths.State, "accounts.json"))
			if !bytes.Equal(metadata, after) {
				t.Fatal("switch rewrote accounts metadata")
			}
			encoded, _ := json.Marshal(result)
			noSwitchSecrets(t, string(encoded))
			assertClaudeLocksReleased(t, f.loc)
		})
	}
}

func assertClaudeLocksReleased(t *testing.T, loc claudecfg.Locations) {
	t.Helper()
	for _, lock := range claudelock.Locks(loc) {
		if _, err := os.Stat(lock.Path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("Claude lock left behind")
		}
	}
}

// Invariant 4: already-active results have an empty warning array and perform no writes.
func TestSwitchAlreadyActive(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		t.Run(platform, func(t *testing.T) {
			f := setupSwitch(t, platform)
			before := f.snapshot(t)
			beforeSwitchWrite = func(string) { t.Fatal("already-active attempted a write") }
			result, err := f.m.Switch("a", f.loc, platform, f.security, SwitchOptions{})
			if err != nil || result.Switched || result.From != "a" || result.To != "a" || result.Warnings == nil || !reflect.DeepEqual(before, f.snapshot(t)) {
				t.Fatal("already-active changed state or result")
			}
			if platform == "darwin" {
				writes, _ := os.ReadFile(filepath.Join(f.keychain, "writes"))
				if len(writes) != 0 {
					t.Fatal("already-active wrote Keychain")
				}
			}
		})
	}
}

// Invariants 5, 14: all validation refusals preserve every stored byte and file mtime.
func TestSwitchRefusalsWriteNothing(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		for _, failure := range []string{"unknown-alias", "unmanaged", "unreadable-live", "unreadable-target", "absent-target", "unreadable-outgoing", "busy", "no-identity", "bad-global", "no-oauth", "target-no-refresh", "target-not-object", "target-bad-identity"} {
			t.Run(platform+"/"+failure, func(t *testing.T) {
				f := setupSwitch(t, platform)
				alias, want := "b", ""
				switch failure {
				case "unknown-alias":
					alias, want = "missing", `no account with alias "missing"`
				case "unmanaged":
					put(t, f.loc.GlobalConfig, []byte(`{"oauthAccount":{"accountUuid":"other","emailAddress":"other@example.com"}}`))
					want = "the active Claude Code login (other@example.com) is not managed by fasthands; run fasthands add first"
				case "unreadable-live":
					if platform == "darwin" {
						t.Setenv("FH_FAIL_READ", f.loc.Service+"/"+f.loc.KeychainAccount)
						put(t, f.loc.CredentialsFile, f.live)
					} else {
						os.Remove(f.loc.CredentialsFile)
						if err := os.Mkdir(f.loc.CredentialsFile, 0700); err != nil {
							t.Fatal(err)
						}
					}
				case "unreadable-target", "unreadable-outgoing":
					id, name := "id-b", "b"
					if failure == "unreadable-outgoing" {
						id, name = "id-a", "a"
					}
					if platform == "darwin" {
						t.Setenv("FH_FAIL_READ", "fasthands/"+id)
					} else {
						os.Remove(f.backupPath(id, false))
						if err := os.Mkdir(f.backupPath(id, false), 0700); err != nil {
							t.Fatal(err)
						}
					}
					want = fmt.Sprintf("stored login for %s is unreadable right now; retry, do not re-add", name)
				case "absent-target":
					if err := os.Remove(f.backupPath("id-b", false)); err != nil {
						t.Fatal(err)
					}
					want = "no stored login for b; log in as it and run fasthands add"
				case "busy":
					if err := os.Mkdir(claudelock.Locks(f.loc)[3].Path, 0700); err != nil {
						t.Fatal(err)
					}
					want = "Claude Code is busy with its credentials; retry in a few seconds"
				case "no-identity":
					put(t, f.loc.GlobalConfig, []byte(`{"other":true}`))
					want = "no active Claude Code login"
				case "bad-global":
					put(t, f.loc.GlobalConfig, []byte(`{"live-access-private": invalid}`))
				case "no-oauth":
					f.setLive(t, []byte(`{"claudeAiOauth":null}`))
					want = "active login is not a Claude OAuth login"
				case "target-no-refresh":
					if err := f.m.Store.Write("id-b", []byte(`{"claudeAiOauth":{"accessToken":"target-access-private"}}`)); err != nil {
						t.Fatal(err)
					}
				case "target-not-object":
					if err := f.m.Store.Write("id-b", []byte(`{"target-access-private": invalid}`)); err != nil {
						t.Fatal(err)
					}
				case "target-bad-identity":
					db, _ := f.m.read()
					account := db.Accounts["id-b"]
					account.OAuthAccount = json.RawMessage(`{"accountUuid":"wrong-id"}`)
					db.Accounts["id-b"] = account
					data, _ := json.Marshal(db)
					put(t, filepath.Join(f.m.Paths.State, "accounts.json"), data)
				}
				before := f.snapshot(t)
				beforeSwitchWrite = func(string) { t.Fatal("refusal attempted a write") }
				_, err := f.m.Switch(alias, f.loc, platform, f.security, SwitchOptions{})
				if err == nil || want != "" && err.Error() != want {
					t.Fatalf("wrong refusal: %v", err)
				}
				noSwitchSecrets(t, err.Error())
				if !reflect.DeepEqual(before, f.snapshot(t)) {
					t.Fatal("refusal changed stored files")
				}
			})
		}
	}
}

// Invariants 6, 7: wiped tokens and proven foreign lineage never overwrite A's recovery copy.
func TestSwitchKeepsOutgoingBackup(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		for _, reason := range []string{"wiped-empty", "wiped-missing", "foreign-lineage"} {
			t.Run(platform+"/"+reason, func(t *testing.T) {
				f := setupSwitch(t, platform)
				live := []byte(`{"claudeAiOauth":{}}`)
				warning := "the active login's tokens were wiped by Claude Code; kept a's stored backup"
				if reason == "wiped-empty" {
					live = []byte(`{"claudeAiOauth":{"accessToken":"","refreshToken":""}}`)
				} else if reason == "foreign-lineage" {
					live = f.target
					warning = "the active login matches b's stored login; not saved into a"
				}
				f.setLive(t, live)
				before, err := os.Stat(f.backupPath("id-a", false))
				if err != nil {
					t.Fatal(err)
				}
				result, err := f.m.Switch("b", f.loc, platform, f.security, SwitchOptions{})
				if err != nil || !result.Switched || !reflect.DeepEqual(result.Warnings, []string{warning}) || !bytes.Equal(f.rawBackup(t, "id-a", false), f.stored) {
					t.Fatalf("protected outgoing backup failed: %v", err)
				}
				after, err := os.Stat(f.backupPath("id-a", false))
				if err != nil || !before.ModTime().Equal(after.ModTime()) {
					t.Fatal("protected backup was rewritten")
				}
				if _, err := os.Stat(f.backupPath("id-a", true)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("protected backup created a previous generation")
				}
				if _, refresh, err := claudecfg.OAuthTokens(f.rawLive(t)); err != nil || refresh != "target-refresh-private" {
					t.Fatal("protected capture prevented target activation")
				}
				noSwitchSecrets(t, strings.Join(result.Warnings, "\n"))
			})
		}
	}
}

// Invariant 8: live failure leaves config alone; config failure restores exact original bytes.
func TestSwitchWriteFailures(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		for _, failure := range []string{"live", "config", "rollback"} {
			t.Run(platform+"/"+failure, func(t *testing.T) {
				f := setupSwitch(t, platform)
				config, _ := os.ReadFile(f.loc.GlobalConfig)
				originalWrite := switchWriteLive
				writes := 0
				if failure == "live" && platform == "darwin" {
					t.Setenv("FH_FAIL_WRITE", f.loc.Service+"/"+f.loc.KeychainAccount)
				} else {
					switchWriteLive = func(loc claudecfg.Locations, platform, security string, keychain bool, blob []byte) error {
						writes++
						if failure == "live" || failure == "rollback" && writes == 2 {
							return errors.New("injected-private")
						}
						return originalWrite(loc, platform, security, keychain, blob)
					}
				}
				if failure != "live" {
					switchWriteConfig = func(string, []byte) error { return errors.New("injected-private") }
				}
				_, err := f.m.Switch("b", f.loc, platform, f.security, SwitchOptions{})
				if err == nil {
					t.Fatal("write failure was ignored")
				}
				if failure == "config" && err.Error() != "switch failed and was rolled back" || failure == "rollback" && err.Error() != "switch failed and the rollback failed: run fasthands switch a to recover" {
					t.Fatal("wrong rollback guidance")
				}
				if failure != "rollback" && !bytes.Equal(f.rawLive(t), f.live) {
					t.Fatal("failure did not retain exact original live bytes")
				}
				afterConfig, _ := os.ReadFile(f.loc.GlobalConfig)
				owned, _ := claudecfg.OwnedCredentials(f.live)
				if !bytes.Equal(config, afterConfig) || !bytes.Equal(f.rawBackup(t, "id-a", false), owned) || !bytes.Equal(f.rawBackup(t, "id-a", true), f.stored) || !bytes.Equal(f.rawBackup(t, "id-b", false), f.target) {
					t.Fatal("failed activation changed config or outgoing recovery copies")
				}
				noSwitchSecrets(t, err.Error())
				assertClaudeLocksReleased(t, f.loc)
			})
		}
	}
}

// Invariant 9: loss before any write stops progress; loss after live activation rolls it back.
func TestSwitchLostLockBetweenWrites(t *testing.T) {
	for _, platform := range []string{"linux", "darwin"} {
		for _, step := range []string{"previous", "backup", "live", "config"} {
			t.Run(platform+"/"+step, func(t *testing.T) {
				f := setupSwitch(t, platform)
				var reached []string
				beforeSwitchWrite = func(current string) {
					reached = append(reached, current)
					if current == step {
						if err := os.Remove(claudelock.Locks(f.loc)[0].Path); err != nil {
							t.Fatal(err)
						}
					}
				}
				_, err := f.m.Switch("b", f.loc, platform, f.security, SwitchOptions{})
				if err == nil || reached[len(reached)-1] != step || !bytes.Equal(f.rawLive(t), f.live) {
					t.Fatal("lost lock allowed further writes or left activated credentials")
				}
				if step == "config" && err.Error() != "switch failed and was rolled back" {
					t.Fatal("lost lock after activation must report rollback")
				}
				config, _ := os.ReadFile(f.loc.GlobalConfig)
				if string(config) != globalConfig {
					t.Fatal("lost lock allowed config write")
				}
				owned, _ := claudecfg.OwnedCredentials(f.live)
				want := f.stored
				if step == "live" || step == "config" {
					want = owned
				}
				if !bytes.Equal(f.rawBackup(t, "id-a", false), want) {
					t.Fatal("lost lock wrote the wrong backup generation")
				}
				noSwitchSecrets(t, err.Error())
				assertClaudeLocksReleased(t, f.loc)
			})
		}
	}
}

// Invariant 11: a macOS fallback activation stays in the file while backups stay in Keychain.
func TestSwitchMacFileFallback(t *testing.T) {
	f := setupSwitch(t, "darwin")
	if err := os.Remove(filepath.Join(f.keychain, f.loc.Service, f.loc.KeychainAccount)); err != nil {
		t.Fatal(err)
	}
	put(t, f.loc.CredentialsFile, f.live)
	result, err := f.m.Switch("b", f.loc, "darwin", f.security, SwitchOptions{})
	if err != nil || !result.Switched || result.Store != "file" {
		t.Fatalf("macOS file fallback failed: %v", err)
	}
	live, err := os.ReadFile(f.loc.CredentialsFile)
	if _, refresh, tokenErr := claudecfg.OAuthTokens(live); err != nil || tokenErr != nil || refresh != "target-refresh-private" {
		t.Fatal("fallback did not activate file credentials")
	}
	if _, err := os.Stat(filepath.Join(f.keychain, f.loc.Service, f.loc.KeychainAccount)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fallback created a live Keychain item")
	}
	if !bytes.Equal(f.rawBackup(t, "id-a", true), f.stored) {
		t.Fatal("fallback failed to preserve previous backup")
	}
}

// Invariant 3: oversized machine keys use live argv, but either oversized backup fails preflight.
func TestSwitchKeychainSizeChecks(t *testing.T) {
	for _, kind := range []string{"live", "backup", "previous"} {
		t.Run(kind, func(t *testing.T) {
			f := setupSwitch(t, "darwin")
			var object map[string]json.RawMessage
			json.Unmarshal(f.live, &object)
			large, _ := json.Marshal(strings.Repeat("x", 6000))
			if kind == "live" {
				object["mcpOAuth"] = large
			} else if kind == "backup" {
				object["ownedLarge"] = large
			} else {
				var stored map[string]json.RawMessage
				json.Unmarshal(f.stored, &stored)
				stored["ownedLarge"] = large
				blob, _ := json.Marshal(stored)
				f.setItem(t, "fasthands", "id-a", blob)
			}
			blob, _ := json.Marshal(object)
			f.setLive(t, blob)
			before := f.snapshot(t)
			result, err := f.m.Switch("b", f.loc, "darwin", f.security, SwitchOptions{})
			calls, _ := os.ReadFile(filepath.Join(f.keychain, "calls"))
			if kind == "live" {
				if err != nil || !result.Switched || !strings.Contains(string(calls), "argv add-generic-password "+f.loc.Service+"/") {
					t.Fatalf("oversized live item failed argv activation: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "4032") || !reflect.DeepEqual(before, f.snapshot(t)) || strings.Contains(string(calls), "add-generic-password") {
				t.Fatal("backup overflow was not refused before every write")
			}
		})
	}
}

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"fasthands/internal/accounts"
	"fasthands/internal/claudecfg"
	"fasthands/internal/claudelock"
)

const secondBlob = `{"claudeAiOauth":{"accessToken":"second-access-private","refreshToken":"second-refresh-private"},"trustedDeviceToken":"second-device-private"}`
const secondIdentity = `{"oauthAccount":{"accountUuid":"second-id","emailAddress":"second@example.com","organizationUuid":"org","future":true},"unrelated":true}`

type commandSwitchFixture struct {
	home, fast, keychain string
	loc                  claudecfg.Locations
}

func setupSwitchCommand(t *testing.T, targetPlatform string) commandSwitchFixture {
	t.Helper()
	home, fast := setupActive(t)
	t.Setenv("CLAUDE_SECURESTORAGE_CONFIG_DIR", home)
	platform = targetPlatform
	f := commandSwitchFixture{home: home, fast: fast}
	var err error
	f.loc, err = claudecfg.Locate()
	if err != nil {
		t.Fatal(err)
	}
	if platform == "darwin" {
		f.keychain = filepath.Join(home, "keychain")
		if err := os.Mkdir(f.keychain, 0700); err != nil {
			t.Fatal(err)
		}
		t.Setenv("FH_KEYCHAIN", f.keychain)
		t.Setenv("FH_FAIL_READ", "")
		t.Setenv("FH_FAIL_WRITE", "")
		writeFixture(t, filepath.Join(f.keychain, "error"), activeBlob)
		script, err := os.ReadFile("../../internal/credstore/testdata/security")
		if err != nil {
			t.Fatal(err)
		}
		securityPath = filepath.Join(home, "security")
		writeFixture(t, securityPath, string(script))
		if err := os.Chmod(securityPath, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, entry := range []struct{ alias, blob, identity string }{
		{"a", activeBlob, activeIdentity}, {"b", secondBlob, secondIdentity},
	} {
		f.setLive(t, entry.blob)
		writeFixture(t, f.loc.GlobalConfig, entry.identity)
		if code, _, err := invoke("add", "--alias", entry.alias); code != 0 {
			t.Fatalf("fixture add failed: %s", err)
		}
	}
	f.setLive(t, activeBlob)
	writeFixture(t, f.loc.GlobalConfig, activeIdentity)
	if platform == "darwin" {
		writeFixture(t, filepath.Join(f.keychain, "calls"), "")
		writeFixture(t, filepath.Join(f.keychain, "writes"), "")
	}
	return f
}

func (f commandSwitchFixture) setLive(t *testing.T, blob string) {
	t.Helper()
	if platform != "darwin" {
		writeFixture(t, f.loc.CredentialsFile, blob)
		return
	}
	dir := filepath.Join(f.keychain, f.loc.Service)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(dir, f.loc.KeychainAccount), hex.EncodeToString([]byte(blob)))
}

// Invariants 1, 4, 6, 11, 13, 14: both platforms expose the same result and correct pickup hint.
func TestSwitchCommandOutput(t *testing.T) {
	for _, targetPlatform := range []string{"linux", "darwin"} {
		for _, mode := range []string{"human", "json", "already-human", "already-json", "warning-json", "warning-human", "fallback-human"} {
			t.Run(targetPlatform+"/"+mode, func(t *testing.T) {
				f := setupSwitchCommand(t, targetPlatform)
				alias, store := "b", "file"
				if targetPlatform == "darwin" {
					store = "keychain"
				}
				if strings.HasPrefix(mode, "already") {
					alias = "a"
				}
				if strings.HasPrefix(mode, "warning") {
					f.setLive(t, `{"claudeAiOauth":{"accessToken":"","refreshToken":""}}`)
				}
				if mode == "fallback-human" && targetPlatform == "darwin" {
					if err := os.Remove(filepath.Join(f.keychain, f.loc.Service, f.loc.KeychainAccount)); err != nil {
						t.Fatal(err)
					}
					writeFixture(t, f.loc.CredentialsFile, activeBlob)
					store = "file"
				}
				args := []string{"switch", alias}
				jsonMode := strings.HasSuffix(mode, "json") || mode == "json"
				if jsonMode {
					args = append(args, "--json")
				}
				code, out, err := invoke(args...)
				if code != 0 {
					t.Fatalf("switch command failed: %s", err)
				}
				if jsonMode {
					var result struct {
						Switched bool     `json:"switched"`
						From     string   `json:"from"`
						To       string   `json:"to"`
						Store    string   `json:"store"`
						Warnings []string `json:"warnings"`
					}
					var shape map[string]json.RawMessage
					if err != "" || json.Unmarshal([]byte(out), &result) != nil || json.Unmarshal([]byte(out), &shape) != nil || len(shape) != 5 || result.Switched != (alias == "b") || result.From != "a" || result.To != alias || result.Store != store || result.Warnings == nil {
						t.Fatal("switch JSON shape differs from contract")
					}
					wantWarnings := 0
					if mode == "warning-json" {
						wantWarnings = 1
					}
					if len(result.Warnings) != wantWarnings || wantWarnings == 0 && string(shape["warnings"]) != `[]` {
						t.Fatal("wrong warning array")
					}
				} else if alias == "a" {
					if out != "a is already active\n" || err != "" {
						t.Fatal("wrong already-active human output")
					}
				} else {
					hint := "running Claude sessions pick it up on their next message\n"
					if store == "keychain" {
						hint = "running Claude sessions pick it up within about 30 seconds\n"
					}
					if out != "switched to b (second@example.com)\n"+hint {
						t.Fatal("wrong switch human output")
					}
					if mode == "warning-human" {
						if err != "warning: the active login's tokens were wiped by Claude Code; kept a's stored backup\n" {
							t.Fatal("human warning missing")
						}
					} else if err != "" {
						t.Fatal("unexpected human warning")
					}
				}
				assertOutputPrivate(t, out+err)
				for _, token := range []string{"second-access-private", "second-refresh-private", "second-device-private"} {
					if strings.Contains(out+err, token) || strings.Contains(out+err, hex.EncodeToString([]byte(token))) {
						t.Fatal("switch exposed target credentials")
					}
				}
			})
		}
	}
}

func TestSwitchCommandUsage(t *testing.T) {
	for _, args := range [][]string{
		{"switch"}, {"switch", "--json"}, {"switch", "a", "b"}, {"switch", "BAD"},
		{"switch", "a.b"}, {"switch", "a", "--json=invalid"}, {"switch", "a", "--alias", "b"},
		{"switch", "a", "--wait", "invalid"}, {"switch", "a", "--wait", "-1s"},
		{"switch", "a", "--wait"}, {"switch", "a", "--force=invalid"},
	} {
		code, out, err := invoke(args...)
		if code != 2 || out != "" || err == "" {
			t.Fatalf("invalid switch arguments did not return 2: %v", args)
		}
	}
	for _, args := range [][]string{{"help"}, {"switch", "--help"}, {"switch", "a", "-h"}} {
		code, out, err := invoke(args...)
		if code != 0 || !strings.Contains(out, "switch ALIAS") || err != "" {
			t.Fatal("switch missing from help")
		}
	}
}

// Slice 3 invariants 6, 7, 9, 10: command refusals stay on stderr; force exposes warnings in either mode.
func TestSwitchCommandMidTurn(t *testing.T) {
	for _, targetPlatform := range []string{"linux", "darwin"} {
		for _, mode := range []string{"refuse-human", "refuse-json", "force-human", "force-json", "already"} {
			t.Run(targetPlatform+"/"+mode, func(t *testing.T) {
				f := setupSwitchCommand(t, targetPlatform)
				dir := filepath.Join(f.home, "sessions")
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(dir, "42.json")
				writeFixture(t, path, "not JSON")
				alias := "b"
				if mode == "already" {
					alias = "a"
				}
				args := []string{"switch", alias}
				if strings.HasPrefix(mode, "force") {
					args = append(args, "--force")
				} else if mode != "already" {
					args = append(args, "--wait", "0")
				}
				if strings.HasSuffix(mode, "json") {
					args = append(args, "--json")
				}
				before := snapshot(t, f.fast)
				config, _ := os.ReadFile(f.loc.GlobalConfig)
				live, inKeychain, readErr := claudecfg.ReadLive(f.loc, platform, securityPath)
				if readErr != nil {
					t.Fatal(readErr)
				}
				code, out, err := invoke(args...)
				message := "1 Claude session(s) mid-turn: unreadable record " + path
				if strings.HasPrefix(mode, "refuse") {
					if code != 1 || out != "" || err != message+"; retry when they finish, or pass --wait or --force\n" {
						t.Fatal("mid-turn command refusal must use stderr and exit 1")
					}
				} else if mode == "force-json" {
					var result accounts.SwitchResult
					if code != 0 || err != "" || json.Unmarshal([]byte(out), &result) != nil || !result.Switched || !reflect.DeepEqual(result.Warnings, []string{message}) {
						t.Fatal("forced JSON switch lost its warning")
					}
				} else if mode == "force-human" {
					if code != 0 || !strings.HasPrefix(out, "switched to b (second@example.com)\n") || err != "warning: "+message+"\n" {
						t.Fatal("forced human switch lost its warning")
					}
				} else if code != 0 || out != "a is already active\n" || err != "" {
					t.Fatal("already-active command must skip waiting")
				}
				if !strings.HasPrefix(mode, "force") {
					afterConfig, _ := os.ReadFile(f.loc.GlobalConfig)
					afterLive, afterKeychain, readErr := claudecfg.ReadLive(f.loc, platform, securityPath)
					if readErr != nil || inKeychain != afterKeychain || !bytes.Equal(config, afterConfig) || !bytes.Equal(live, afterLive) || !reflect.DeepEqual(before, snapshot(t, f.fast)) {
						t.Fatal("refused or already-active command changed state")
					}
				}
			})
		}
	}
}

func TestAddDoesNotWaitForSessions(t *testing.T) {
	for _, targetPlatform := range []string{"linux", "darwin"} {
		t.Run(targetPlatform, func(t *testing.T) {
			f := setupSwitchCommand(t, targetPlatform)
			dir := filepath.Join(f.home, "sessions")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			writeFixture(t, filepath.Join(dir, "42.json"), "not JSON")
			if code, _, err := invoke("add", "--json"); code != 0 || err != "" {
				t.Fatal("capturing current login must not wait for sessions")
			}
		})
	}
}

// Invariants 5, 14: command refusals use exit 1 and one safe stderr line.
func TestSwitchCommandRefusal(t *testing.T) {
	for _, targetPlatform := range []string{"linux", "darwin"} {
		t.Run(targetPlatform, func(t *testing.T) {
			f := setupSwitchCommand(t, targetPlatform)
			before := snapshot(t, f.fast)
			code, out, err := invoke("switch", "missing", "--json")
			if code != 1 || out != "" || err != "no account with alias \"missing\"\n" || !reflect.DeepEqual(before, snapshot(t, f.fast)) {
				t.Fatal("unknown alias did not produce safe refusal")
			}
			f.setLive(t, `{"cli-access-private":invalid}`)
			code, out, err = invoke("switch", "b", "--json")
			if code != 1 || out != "" || err != "active login is not a Claude OAuth login\n" {
				t.Fatal("malformed active login did not produce safe refusal")
			}
			assertOutputPrivate(t, out+err)
		})
	}
}

// Invariant 12: add cannot read a login or create fasthands state while Claude owns a lock.
func TestAddBusyClaudeLockWritesNothing(t *testing.T) {
	for _, targetPlatform := range []string{"linux", "darwin"} {
		t.Run(targetPlatform, func(t *testing.T) {
			f := setupSwitchCommand(t, targetPlatform)
			oldTimeout := claudeLockTimeout
			claudeLockTimeout = 10 * time.Millisecond
			t.Cleanup(func() { claudeLockTimeout = oldTimeout })
			if err := os.RemoveAll(f.fast); err != nil {
				t.Fatal(err)
			}
			locks := claudelock.Locks(f.loc)
			if err := os.Mkdir(locks[3].Path, 0700); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(f.loc.GlobalConfig)
			code, out, err := invoke("add", "--json")
			if code != 1 || out != "" || err != "Claude Code is busy with its credentials; retry in a few seconds\n" {
				t.Fatal("busy Claude lock did not block add")
			}
			if _, err := os.Stat(f.fast); !os.IsNotExist(err) {
				t.Fatal("busy add created fasthands state")
			}
			after, _ := os.ReadFile(f.loc.GlobalConfig)
			if !bytes.Equal(before, after) {
				t.Fatal("busy add changed global config")
			}
			for _, lock := range locks[:3] {
				if _, err := os.Stat(lock.Path); !os.IsNotExist(err) {
					t.Fatal("busy add leaked acquired lock")
				}
			}
			if targetPlatform == "darwin" {
				calls, _ := os.ReadFile(filepath.Join(f.keychain, "calls"))
				if len(calls) != 0 {
					t.Fatal("busy add read Keychain")
				}
			}
		})
	}
}

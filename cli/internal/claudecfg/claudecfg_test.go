package claudecfg

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const credentials = `{"claudeAiOauth":{"accessToken":"capture-access-private","refreshToken":"capture-refresh-private"}}`
const identity = `{"oauthAccount":{"accountUuid":"account-uuid","emailAddress":"Person@example.com","organizationUuid":"org","future":{"keep":true}}}`

func TestServiceHash(t *testing.T) {
	for _, tt := range []struct {
		raw, suffix string
		set         bool
	}{
		{"", "", false},
		{"/Users/3li/.claude-work", "-ade7974e", true},
		{"/tmp/fh test", "-2d0e408f", true},
		{"", "", true}, // Claude Code treats empty as unset
	} {
		got, err := Service(tt.raw, tt.set)
		if err != nil || got != "Claude Code-credentials"+tt.suffix {
			t.Fatalf("wrong service for %q", tt.raw)
		}
	}
	a, _ := Service("/tmp/a", true)
	b, _ := Service("/tmp/a/", true)
	c, _ := Service("/tmp/./a", true)
	if a == b || a == c {
		t.Fatal("raw config value must not be cleaned")
	}
}

func TestServiceEmptyEnvIsUnset(t *testing.T) {
	if got, err := Service("", true); err != nil || got != "Claude Code-credentials" {
		t.Fatalf("empty CLAUDE_CONFIG_DIR must read the default service, got %q %v", got, err)
	}
}

func TestServiceRefusesNonASCII(t *testing.T) {
	for _, raw := range []string{"/tmp/caf\u00e9", "/tmp/cafe\u0301", "/tmp/\xff"} {
		if _, err := Service(raw, true); err == nil || !strings.Contains(err.Error(), "NFC") {
			t.Fatal("non-ASCII service hash must fail clearly")
		}
	}
}

func TestGlobalConfigSelection(t *testing.T) {
	for _, tt := range []struct {
		name                     string
		modern, legacy, wantNew  bool
		content                  string
		mode                     os.FileMode
		directory, symlink, loop bool
	}{
		{name: "nonempty", modern: true, legacy: true, wantNew: true, content: "{}", mode: 0400},
		{name: "empty-writable-no-legacy", modern: true, wantNew: true, mode: 0200},
		{name: "empty-writable-with-legacy", modern: true, legacy: true, mode: 0600},
		{name: "empty-readonly-no-legacy", modern: true, mode: 0400},
		{name: "absent", legacy: true},
		{name: "directory", directory: true, legacy: true},
		{name: "symlink-to-regular", modern: true, symlink: true, content: "{}", mode: 0600, wantNew: true},
		{name: "stat-error", loop: true, legacy: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			base := t.TempDir()
			home := filepath.Join(base, ".claude")
			if err := os.Mkdir(home, 0700); err != nil {
				t.Fatal(err)
			}
			modern := filepath.Join(home, ".config.json")
			legacy := filepath.Join(base, ".claude.json")
			if tt.modern {
				target := modern
				if tt.symlink {
					target = filepath.Join(base, "target")
					if err := os.Symlink(target, modern); err != nil {
						t.Fatal(err)
					}
				}
				write(t, target, tt.content)
				if err := os.Chmod(target, tt.mode); err != nil {
					t.Fatal(err)
				}
			}
			if tt.directory {
				if err := os.Mkdir(modern, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if tt.loop {
				if err := os.Symlink(modern, modern); err != nil {
					t.Fatal(err)
				}
			}
			if tt.legacy {
				write(t, legacy, "{}")
			}
			want := legacy
			if tt.wantNew {
				want = modern
			}
			if got := GlobalConfig(home, base); got != want {
				t.Fatalf("wrong config: %s", got)
			}
		})
	}
}

func TestAccountCredentialsStripOnlySharedKeys(t *testing.T) {
	var original map[string]json.RawMessage
	if err := json.Unmarshal([]byte(credentials), &original); err != nil {
		t.Fatal("invalid fixture")
	}
	shared := []string{"mcpOAuth", "mcpOAuthClientConfig", "mcpXaaIdp", "mcpXaaIdpConfig", "pluginSecrets"}
	for _, key := range shared {
		original[key] = json.RawMessage(`{"machine":"shared"}`)
	}
	original["trustedDeviceToken"] = json.RawMessage(`"keep-private-device"`)
	original["unknownFutureKey"] = json.RawMessage(`{"nested":[1,true,"keep"]}`)
	data, _ := json.Marshal(original)
	owned, err := accountCredentials(data)
	if err != nil {
		t.Fatal("valid credentials rejected")
	}
	var got map[string]json.RawMessage
	if json.Unmarshal(owned, &got) != nil {
		t.Fatal("backup is not JSON")
	}
	for _, key := range shared {
		if _, ok := got[key]; ok {
			t.Fatalf("shared key retained: %s", key)
		}
		delete(original, key)
	}
	if !reflect.DeepEqual(got, original) {
		t.Fatal("account-owned key changed or disappeared")
	}
}

func TestInvalidCredentials(t *testing.T) {
	for _, blob := range []string{
		`not-json-capture-access-private`, `null`, `[]`, `{}`, `{"claudeAiOauth":null}`,
		`{"claudeAiOauth":{"accessToken":"a"}}`, `{"claudeAiOauth":{"accessToken":"","refreshToken":"r"}}`,
		`{"claudeAiOauth":{"accessToken":123,"refreshToken":"r"}}`, `{"claudeAiOauth":{"accessToken":"a","refreshToken":null}}`,
		`{"claudeAiOauth":{"AccessToken":"a","refreshToken":"r"}}`, `{"claudeAiOauth":{"accessToken":"a","RefreshToken":"r"}}`,
	} {
		if _, err := accountCredentials([]byte(blob)); err == nil {
			t.Fatal("invalid login accepted")
		}
	}
}

func TestReadDefaultAndOverrideLocations(t *testing.T) {
	for _, mode := range []string{"unset", "empty", "override"} {
		t.Run(mode, func(t *testing.T) {
			base := t.TempDir()
			t.Setenv("HOME", base)
			t.Setenv("CLAUDE_CONFIG_DIR", "")
			home := filepath.Join(base, ".claude")
			if mode == "unset" {
				if err := os.Unsetenv("CLAUDE_CONFIG_DIR"); err != nil {
					t.Fatal(err)
				}
			} else if mode == "override" {
				home = filepath.Join(base, "custom")
				base = home
				t.Setenv("CLAUDE_CONFIG_DIR", home)
			}
			if err := os.MkdirAll(home, 0700); err != nil {
				t.Fatal(err)
			}
			write(t, filepath.Join(home, ".credentials.json"), credentials)
			write(t, filepath.Join(base, ".claude.json"), identity)
			capture, err := Read("linux", "/never-run")
			if err != nil || capture.AccountUUID != "account-uuid" || capture.Email != "Person@example.com" || capture.OrganizationUUID != "org" {
				t.Fatal("capture from resolved config failed")
			}
			if !strings.Contains(string(capture.OAuthAccount), `"future"`) {
				t.Fatal("full oauthAccount must survive capture")
			}
		})
	}
}

func TestMacKeychainFallbackOnlyOnAbsent(t *testing.T) {
	for _, code := range []string{"0", "44", "1"} {
		t.Run(code, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("CLAUDE_CONFIG_DIR", dir)
			write(t, filepath.Join(dir, ".credentials.json"), credentials)
			write(t, filepath.Join(dir, ".config.json"), identity)
			keychainBlob := strings.Replace(credentials, "capture-access-private", "keychain-access-private", 1)
			write(t, filepath.Join(dir, "reply"), keychainBlob)
			t.Setenv("FH_REPLY", filepath.Join(dir, "reply"))
			t.Setenv("FH_ARGS", filepath.Join(dir, "argv"))
			t.Setenv("FH_EXIT", code)
			script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$FH_ARGS\"\ncat \"$FH_REPLY\"\ncat \"$FH_REPLY\" >&2\nexit \"$FH_EXIT\"\n"
			security := filepath.Join(dir, "security")
			write(t, security, script)
			if err := os.Chmod(security, 0700); err != nil {
				t.Fatal(err)
			}
			capture, err := Read("darwin", security)
			if code == "1" {
				if err == nil || !strings.Contains(err.Error(), "unreadable") || strings.Contains(err.Error(), "private") {
					t.Fatal("unreadable Keychain must not fall back or leak stderr")
				}
				return
			}
			want := credentials
			if code == "0" {
				want = keychainBlob
			}
			if err != nil || string(capture.Credentials) != want {
				t.Fatal("wrong active credential source")
			}
			current, userErr := user.Current()
			if userErr != nil {
				t.Fatal(userErr)
			}
			args, _ := os.ReadFile(filepath.Join(dir, "argv"))
			if !strings.Contains(string(args), "\n"+current.Username+"\n") {
				t.Fatal("Keychain read must use os/user username")
			}
		})
	}
}

func TestInvalidIdentityAndSafeErrors(t *testing.T) {
	for _, config := range []string{`not-json-capture-access-private`, `{}`, `{"oauthAccount":null}`, `{"oauthAccount":{"accountUuid":""}}`, `{"oauthAccount":{"accountUuid":123}}`, `{"OAuthAccount":{"accountUuid":"id"}}`, `{"oauthAccount":{"AccountUuid":"id"}}`} {
		dir := t.TempDir()
		t.Setenv("CLAUDE_CONFIG_DIR", dir)
		write(t, filepath.Join(dir, ".credentials.json"), credentials)
		write(t, filepath.Join(dir, ".config.json"), config)
		_, err := Read("linux", "/unused")
		if err == nil || !strings.Contains(err.Error(), filepath.Join(dir, ".config.json")) || strings.Contains(err.Error(), "private") {
			t.Fatal("invalid identity must fail without quoting config")
		}
	}
}

func write(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}

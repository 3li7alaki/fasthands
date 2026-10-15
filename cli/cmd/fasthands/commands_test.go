package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"fasthands/internal/accounts"
	"fasthands/internal/claudecfg"
)

const activeBlob = `{"claudeAiOauth":{"accessToken":"cli-access-private","refreshToken":"cli-refresh-private"},"trustedDeviceToken":"device-private","unknown":{"keep":true},"mcpOAuth":{"shared":true},"mcpOAuthClientConfig":{},"mcpXaaIdp":{},"mcpXaaIdpConfig":{},"pluginSecrets":{}}`
const activeIdentity = `{"oauthAccount":{"accountUuid":"12345678-1234-1234-1234-123456789abc","emailAddress":"Person@example.com","organizationUuid":"org","future":"keep"}}`

func setupActive(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "claude")
	fast := filepath.Join(root, "fasthands")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", root)
	t.Setenv("USER", "test-user")
	t.Setenv("CLAUDE_CONFIG_DIR", home)
	t.Setenv("CLAUDE_SECURESTORAGE_CONFIG_DIR", "")
	if err := os.Unsetenv("CLAUDE_SECURESTORAGE_CONFIG_DIR"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FASTHANDS_HOME", fast)
	writeFixture(t, filepath.Join(home, ".credentials.json"), activeBlob)
	writeFixture(t, filepath.Join(home, ".config.json"), activeIdentity)
	oldPlatform, oldSecurity := platform, securityPath
	platform = "linux"
	t.Cleanup(func() { platform, securityPath = oldPlatform, oldSecurity })
	return home, fast
}

func invoke(args ...string) (int, string, string) {
	var out, err bytes.Buffer
	code := run(args, &out, &err)
	return code, out.String(), err.String()
}

func TestEmptyListJSON(t *testing.T) {
	_, fast := setupActive(t)
	code, out, err := invoke("ls", "--json")
	if code != 0 || out != "{\"accounts\":[]}\n" || err != "" {
		t.Fatal("empty ls --json must print an empty array")
	}
	if _, err := os.Stat(fast); !os.IsNotExist(err) {
		t.Fatal("ls must not create empty store")
	}
}

func TestAddAndListCommands(t *testing.T) {
	_, fast := setupActive(t)
	code, out, err := invoke("add", "--json")
	var result accounts.Result
	if code != 0 || err != "" || json.Unmarshal([]byte(out), &result) != nil || result.Alias != "person" || result.Updated || result.Store != "file" {
		t.Fatal("add --json failed")
	}
	assertOutputPrivate(t, out+err)
	code, out, err = invoke("add")
	if code != 0 || err != "" || out != "updated person (Person@example.com)\n" {
		t.Fatal("re-add must keep alias and report update")
	}
	code, out, err = invoke("add", "--alias", "work", "--json")
	if code != 0 || err != "" || json.Unmarshal([]byte(out), &result) != nil || result.Alias != "work" || !result.Updated {
		t.Fatal("explicit alias update failed")
	}
	code, out, err = invoke("ls")
	if code != 0 || err != "" || !strings.HasPrefix(out, "work\tPerson@example.com\t12345678\t") || !strings.HasSuffix(out, "\tfile\n") {
		t.Fatal("human list must show alias, email, short uuid, addedAt and store")
	}
	code, out, err = invoke("ls", "--json")
	var listed struct {
		Accounts []accounts.Listed `json:"accounts"`
	}
	if code != 0 || err != "" || json.Unmarshal([]byte(out), &listed) != nil || len(listed.Accounts) != 1 || listed.Accounts[0].AccountUUID != result.AccountUUID {
		t.Fatal("list JSON must contain stored account")
	}
	assertOutputPrivate(t, out+err)
	metadata, readErr := os.ReadFile(filepath.Join(fast, "state", "accounts.json"))
	if readErr != nil || !strings.Contains(string(metadata), `"future": "keep"`) {
		t.Fatal("metadata must retain full oauthAccount")
	}
	assertOutputPrivate(t, string(metadata))
	backup, readErr := os.ReadFile(filepath.Join(fast, "credentials", result.AccountUUID+".json"))
	var owned map[string]json.RawMessage
	if readErr != nil || json.Unmarshal(backup, &owned) != nil || len(owned) != 3 || owned["trustedDeviceToken"] == nil || owned["unknown"] == nil {
		t.Fatal("backup must retain only account-owned keys")
	}
}

func TestHumanAdd(t *testing.T) {
	setupActive(t)
	code, out, err := invoke("add", "--alias", "home")
	if code != 0 || err != "" || out != "added home (Person@example.com)\n" {
		t.Fatal("human add output differs from contract")
	}
}

func TestAddReadsSeparateStorage(t *testing.T) {
	home, fast := setupActive(t)
	storage := t.TempDir()
	t.Setenv("CLAUDE_SECURESTORAGE_CONFIG_DIR", storage)
	writeFixture(t, filepath.Join(home, ".credentials.json"), "not-json-cli-access-private")
	writeFixture(t, filepath.Join(storage, ".credentials.json"), activeBlob)
	code, out, err := invoke("add", "--json")
	var result accounts.Result
	if code != 0 || err != "" || json.Unmarshal([]byte(out), &result) != nil || result.Store != "file" {
		t.Fatal("add must capture credentials from secure-storage override")
	}
	assertOutputPrivate(t, out+err)
	backup, readErr := os.ReadFile(filepath.Join(fast, "credentials", result.AccountUUID+".json"))
	if readErr != nil || !bytes.Contains(backup, []byte("cli-access-private")) {
		t.Fatal("add did not back up the storage directory login")
	}
}

func TestCommandUsageAndHelp(t *testing.T) {
	for _, args := range [][]string{
		{"unknown"}, {"add", "--alias"}, {"add", "--alias", ""}, {"add", "--alias", "BAD"},
		{"ls", "--alias", "name"}, {"ls", "extra"}, {"add", "--json=invalid"},
	} {
		code, out, err := invoke(args...)
		if code != 2 || out != "" || err == "" {
			t.Fatalf("invalid arguments must return usage exit 2: %v", args)
		}
	}
	for _, args := range [][]string{{"help"}, {"add", "--help"}, {"ls", "-h"}} {
		code, out, err := invoke(args...)
		if code != 0 || out == "" || err != "" {
			t.Fatalf("help must use stdout and exit 0: %v", args)
		}
	}
	code, out, err := invoke("--version", "--json")
	if code != 0 || err != "" || !json.Valid([]byte(out)) {
		t.Fatal("version --json must be JSON")
	}
}

func TestFailedSourceReadChangesNothing(t *testing.T) {
	for _, failure := range []string{"missing-credentials", "credentials-directory", "malformed-credentials", "missing-global", "global-directory", "malformed-global", "missing-account-uuid"} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/existing=%t", failure, existing), func(t *testing.T) {
				home, fast := setupActive(t)
				if existing {
					if code, _, _ := invoke("add"); code != 0 {
						t.Fatal("initial capture failed")
					}
				}
				before := snapshot(t, fast)
				credentialsPath := filepath.Join(home, ".credentials.json")
				globalPath := filepath.Join(home, ".config.json")
				switch failure {
				case "missing-credentials", "credentials-directory":
					if err := os.Remove(credentialsPath); err != nil {
						t.Fatal(err)
					}
					if failure == "credentials-directory" {
						if err := os.Mkdir(credentialsPath, 0700); err != nil {
							t.Fatal(err)
						}
					}
				case "malformed-credentials":
					writeFixture(t, credentialsPath, `{"cli-access-private": invalid}`)
				case "missing-global", "global-directory":
					if err := os.Remove(globalPath); err != nil {
						t.Fatal(err)
					}
					if failure == "global-directory" {
						if err := os.Mkdir(filepath.Join(home, ".claude.json"), 0700); err != nil {
							t.Fatal(err)
						}
					}
				case "malformed-global":
					writeFixture(t, globalPath, `{"cli-refresh-private": invalid}`)
				case "missing-account-uuid":
					writeFixture(t, globalPath, `{"oauthAccount":{"emailAddress":"person@example.com"}}`)
				}
				code, out, err := invoke("add", "--json")
				if code != 1 || out != "" || err == "" {
					t.Fatal("bad source must return error on stderr")
				}
				assertOutputPrivate(t, out+err)
				if !reflect.DeepEqual(before, snapshot(t, fast)) {
					t.Fatal("failed source read changed stored files")
				}
			})
		}
	}
}

func TestMacCommandWithFakeSecurity(t *testing.T) {
	home, fast := setupActive(t)
	platform = "darwin"
	t.Setenv("CLAUDE_SECURESTORAGE_CONFIG_DIR", home)
	t.Setenv("USER", "fh.user-1")
	argvPath, stdinPath := filepath.Join(home, "argv"), filepath.Join(home, "stdin")
	t.Setenv("FH_ARGS", argvPath)
	t.Setenv("FH_STDIN", stdinPath)
	t.Setenv("FH_REPLY", filepath.Join(home, ".credentials.json"))
	t.Setenv("FH_EXIT", "0")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$FH_ARGS\"\nif [ \"$1\" = '-i' ]; then\ncat > \"$FH_STDIN\"\nelse\ncat \"$FH_REPLY\"\ncat \"$FH_REPLY\" >&2\nfi\nexit \"$FH_EXIT\"\n"
	securityPath = filepath.Join(home, "security")
	writeFixture(t, securityPath, script)
	if err := os.Chmod(securityPath, 0700); err != nil {
		t.Fatal(err)
	}
	code, out, err := invoke("add", "--json")
	var result accounts.Result
	if code != 0 || err != "" || json.Unmarshal([]byte(out), &result) != nil || result.Store != "keychain" {
		t.Fatal("macOS add through fake security failed")
	}
	assertOutputPrivate(t, out+err)
	service, _ := claudecfg.Service(home, true)
	args, readErr := os.ReadFile(argvPath)
	if readErr != nil || string(args) != "find-generic-password\n-a\nfh.user-1\n-s\n"+service+"\n-w\n-i\n" {
		t.Fatal("macOS add must use resolved read identifiers and write through security -i")
	}
	assertOutputPrivate(t, string(args))
	stdin, readErr := os.ReadFile(stdinPath)
	if readErr != nil {
		t.Fatal("missing interactive write")
	}
	parts := strings.SplitN(strings.TrimSuffix(string(stdin), "\n"), " -X ", 2)
	if len(parts) != 2 {
		t.Fatal("missing hex input")
	}
	blob, decodeErr := hex.DecodeString(strings.Trim(parts[1], `"`))
	var owned map[string]json.RawMessage
	if decodeErr != nil || json.Unmarshal(blob, &owned) != nil || len(owned) != 3 {
		t.Fatal("Keychain backup did not strip shared keys")
	}
	before := snapshot(t, fast)
	t.Setenv("FH_EXIT", "1")
	code, out, err = invoke("add", "--json")
	if code != 1 || out != "" || !strings.Contains(err, "unreadable") {
		t.Fatal("unreadable Keychain must fail despite valid file fallback")
	}
	assertOutputPrivate(t, err)
	if !reflect.DeepEqual(before, snapshot(t, fast)) {
		t.Fatal("unreadable Keychain changed account storage")
	}
	afterInput, _ := os.ReadFile(stdinPath)
	if !bytes.Equal(stdin, afterInput) {
		t.Fatal("unreadable Keychain overwrote backup")
	}
	if err := os.Remove(filepath.Join(home, ".config.json")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FH_EXIT", "0")
	code, out, err = invoke("add", "--json")
	if code != 1 || out != "" || err == "" || !reflect.DeepEqual(before, snapshot(t, fast)) {
		t.Fatal("failed global read must preserve macOS storage")
	}
	afterInput, _ = os.ReadFile(stdinPath)
	if !bytes.Equal(stdin, afterInput) {
		t.Fatal("failed global read overwrote Keychain backup")
	}
}

func TestCommandModesUnderUmaskZero(t *testing.T) {
	_, fast := setupActive(t)
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	if code, _, _ := invoke("add"); code != 0 {
		t.Fatal("capture under umask 000 failed")
	}
	err := filepath.Walk(fast, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		want := os.FileMode(0600)
		if info.IsDir() {
			want = 0700
		}
		if info.Mode().Perm() != want || strings.HasSuffix(path, ".tmp") {
			t.Fatal("unsafe mode or temporary file left in store")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type fileSnapshot struct {
	Mode    os.FileMode
	ModTime int64
	Hash    [32]byte
}

func snapshot(t *testing.T, root string) map[string]fileSnapshot {
	t.Helper()
	files := map[string]fileSnapshot{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		var data []byte
		if !info.IsDir() {
			data, err = os.ReadFile(path)
			if err != nil {
				return err
			}
		}
		files[path] = fileSnapshot{info.Mode(), info.ModTime().UnixNano(), sha256.Sum256(data)}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func assertOutputPrivate(t *testing.T, output string) {
	t.Helper()
	for _, token := range []string{"cli-access-private", "cli-refresh-private", "device-private"} {
		if strings.Contains(output, token) || strings.Contains(strings.ToLower(output), hex.EncodeToString([]byte(token))) {
			t.Fatal("command exposed credential")
		}
	}
}

func writeFixture(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}

package credstore

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testBlob = `{"claudeAiOauth":{"accessToken":"test-access-private","refreshToken":"test-refresh-private"}}`

func fakeSecurity(t *testing.T, exit string) (Keychain, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("FH_ARGV", filepath.Join(dir, "argv"))
	t.Setenv("FH_STDIN", filepath.Join(dir, "stdin"))
	t.Setenv("FH_REPLY", filepath.Join(dir, "reply"))
	t.Setenv("FH_EXIT", exit)
	if err := os.WriteFile(filepath.Join(dir, "reply"), []byte(testBlob), 0600); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$FH_ARGV\"\ncat > \"$FH_STDIN\"\ncat \"$FH_REPLY\"\ncat \"$FH_REPLY\" >&2\nexit \"$FH_EXIT\"\n"
	path := filepath.Join(dir, "security")
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return Keychain{SecurityPath: path}, dir
}

func TestKeychainRead(t *testing.T) {
	for _, code := range []string{"0", "44", "1"} {
		t.Run(code, func(t *testing.T) {
			k, dir := fakeSecurity(t, code)
			blob, err := k.Read("username", "Claude Code-credentials")
			if code == "0" {
				if err != nil || string(blob) != testBlob {
					t.Fatal("Keychain read failed")
				}
			} else if code == "44" {
				if !errors.Is(err, ErrAbsent) || blob != nil {
					t.Fatal("exit 44 must mean absent")
				}
			} else if err == nil || errors.Is(err, ErrAbsent) || blob != nil || !strings.Contains(err.Error(), "unreadable") {
				t.Fatal("non-44 failure must mean unreadable")
			}
			if err != nil {
				assertNoSecret(t, err.Error())
			}
			argv, readErr := os.ReadFile(filepath.Join(dir, "argv"))
			if readErr != nil || string(argv) != "find-generic-password\n-a\nusername\n-s\nClaude Code-credentials\n-w\n" {
				t.Fatal("wrong Keychain read arguments")
			}
			assertNoSecret(t, string(argv))
		})
	}
}

func TestKeychainWriteUsesOnlyStdin(t *testing.T) {
	k, dir := fakeSecurity(t, "0")
	if err := k.Write("account-uuid", []byte(testBlob)); err != nil {
		t.Fatal("Keychain write failed")
	}
	argv, err := os.ReadFile(filepath.Join(dir, "argv"))
	if err != nil || string(argv) != "-i\n" {
		t.Fatal("Keychain write must invoke only security -i")
	}
	assertNoSecret(t, string(argv))
	stdin, err := os.ReadFile(filepath.Join(dir, "stdin"))
	want := "add-generic-password -U -a account-uuid -s fasthands -X " + hex.EncodeToString([]byte(testBlob)) + "\n"
	if err != nil || string(stdin) != want || bytes.Count(stdin, []byte("\n")) != 1 {
		t.Fatal("Keychain write must send exactly one hex command on stdin")
	}
}

func TestKeychainWriteLineLimit(t *testing.T) {
	k, dir := fakeSecurity(t, "0")
	account := "id"
	overhead := len("add-generic-password -U -a " + account + " -s fasthands -X \n")
	if overhead%2 != 0 {
		account += "x"
		overhead++
	}
	blob := bytes.Repeat([]byte("x"), (4032-overhead)/2)
	if err := k.Write(account, blob); err != nil {
		t.Fatal("exact 4032-byte line must succeed")
	}
	stdin, err := os.ReadFile(filepath.Join(dir, "stdin"))
	if err != nil || len(stdin) != 4032 {
		t.Fatal("test did not reach exact buffer ceiling")
	}
	if err := os.Remove(filepath.Join(dir, "argv")); err != nil {
		t.Fatal(err)
	}
	if err := k.Write(account, append(blob, 'x')); err == nil {
		t.Fatal("oversized line must fail")
	}
	if _, err := os.Stat(filepath.Join(dir, "argv")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("oversized write invoked security")
	}
}

func TestKeychainWriteFailureSanitized(t *testing.T) {
	k, _ := fakeSecurity(t, "1")
	err := k.Write("account", []byte(testBlob))
	if err == nil {
		t.Fatal("failed write must return error")
	}
	assertNoSecret(t, err.Error())
}

func TestKeychainTimeoutAndMissingBinaryAreUnreadable(t *testing.T) {
	old := securityTimeout
	securityTimeout = 50 * time.Millisecond
	defer func() { securityTimeout = old }()
	k, dir := fakeSecurity(t, "0")
	if err := os.WriteFile(k.SecurityPath, []byte("#!/bin/sh\nexec sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{k.SecurityPath, filepath.Join(dir, "missing-security")} {
		_, err := (Keychain{SecurityPath: path}).Read("account", "Claude Code-credentials")
		if err == nil || errors.Is(err, ErrAbsent) || !strings.Contains(err.Error(), "unreadable") {
			t.Fatal("timeout or missing binary must never mean absent")
		}
		assertNoSecret(t, err.Error())
	}
}

func TestBackendSelectionAndFileWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "credentials")
	if New("darwin", "/unused", dir).Kind() != "keychain" {
		t.Fatal("darwin must use Keychain")
	}
	for _, platform := range []string{"linux", "other"} {
		backend := New(platform, "/unused", dir)
		if backend.Kind() != "file" || backend.Write("account", []byte(testBlob)) != nil {
			t.Fatal("non-darwin must use files")
		}
	}
	data, err := os.ReadFile(filepath.Join(dir, "account.json"))
	if err != nil || string(data) != testBlob {
		t.Fatal("file backup changed credentials")
	}
}

func TestRejectUnsafeAccounts(t *testing.T) {
	k, dir := fakeSecurity(t, "0")
	for _, account := range []string{"", ".", "..", "../escape", "a/b", "a\\b", "a\ncommand", "a\rcommand", "a\x00b"} {
		for _, backend := range []Backend{k, Files{Directory: filepath.Join(dir, "credentials")}} {
			if err := backend.Write(account, []byte(testBlob)); err == nil {
				t.Fatal("unsafe account accepted")
			}
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "argv")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unsafe account invoked security")
	}
}

func assertNoSecret(t *testing.T, value string) {
	t.Helper()
	for _, token := range []string{"test-access-private", "test-refresh-private"} {
		encoded := hex.EncodeToString([]byte(token))
		if strings.Contains(value, token) || strings.Contains(strings.ToLower(value), encoded) {
			t.Fatal("credential escaped into output or argv")
		}
	}
}

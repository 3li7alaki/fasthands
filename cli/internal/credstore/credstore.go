// Package credstore stores account backups in Keychain or private files.
package credstore

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"fasthands/internal/statehome"
)

var ErrAbsent = errors.New("stored credentials absent")

// Bound OS prompt waits; a locked or stalled Keychain must remain unreadable.
var securityTimeout = 10 * time.Second

type Backend interface {
	Kind() string
	Read(account string) ([]byte, error)
	Write(account string, blob []byte) error
	WritePrev(account string, blob []byte) error
}

func New(platform, securityPath, directory string) Backend {
	if platform == "darwin" {
		return Keychain{SecurityPath: securityPath}
	}
	return Files{Directory: directory}
}

// ValidAccount prevents captured identifiers from escaping the credentials directory.
func ValidAccount(account string) bool {
	return account != "" && account != "." && account != ".." &&
		!strings.ContainsAny(account, "/\\\x00\r\n")
}

type Files struct{ Directory string }

func (Files) Kind() string { return "file" }

func (f Files) Read(account string) ([]byte, error) {
	if !ValidAccount(account) {
		return nil, errors.New("invalid accountUuid for credential storage")
	}
	path := filepath.Join(f.Directory, account+".json")
	blob, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrAbsent
	}
	if err != nil {
		return nil, fmt.Errorf("unreadable credentials at %q", path)
	}
	return blob, nil
}

func (f Files) Write(account string, blob []byte) error {
	return f.write(account, ".json", blob)
}

func (f Files) WritePrev(account string, blob []byte) error {
	return f.write(account, ".prev.json", blob)
}

func (f Files) write(account, suffix string, blob []byte) error {
	if !ValidAccount(account) {
		return errors.New("invalid accountUuid for credential storage")
	}
	path := filepath.Join(f.Directory, account+suffix)
	if err := statehome.AtomicWrite(path, blob); err != nil {
		return fmt.Errorf("cannot write credentials at %q", path)
	}
	return nil
}

type Keychain struct{ SecurityPath string }

func (Keychain) Kind() string { return "keychain" }

func (k Keychain) command(args ...string) (*exec.Cmd, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), securityTimeout)
	cmd := exec.CommandContext(ctx, k.SecurityPath, args...)
	cmd.Stderr = io.Discard
	return cmd, cancel
}

func (k Keychain) Read(account string) ([]byte, error) {
	if !ValidAccount(account) {
		return nil, errors.New("invalid accountUuid for credential storage")
	}
	return k.ReadService(account, "fasthands")
}

func (k Keychain) ReadService(account, service string) ([]byte, error) {
	cmd, cancel := k.command("find-generic-password", "-a", account, "-s", service, "-w")
	defer cancel()
	blob, err := cmd.Output()
	if err == nil {
		return blob, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 44 {
		return nil, ErrAbsent
	}
	// Never include subprocess stderr or its error, which can quote credentials.
	return nil, fmt.Errorf("unreadable Keychain service %q", service)
}

func (k Keychain) Write(account string, blob []byte) error {
	return k.writeBackup(account, "fasthands", blob)
}

func (k Keychain) WritePrev(account string, blob []byte) error {
	return k.writeBackup(account, "fasthands-prev", blob)
}

func (k Keychain) writeBackup(account, service string, blob []byte) error {
	if !ValidAccount(account) {
		return errors.New("invalid accountUuid for credential storage")
	}
	line, err := interactiveLine(account, service, blob)
	if err != nil {
		return err
	}
	if err := checkLine(line, service); err != nil {
		return err
	}
	return k.writeLine(line, service)
}

// CheckBackup validates every planned backup before switch makes its first write.
func CheckBackup(account string, blob []byte, previous bool) error {
	service := "fasthands"
	if previous {
		service = "fasthands-prev"
	}
	if !ValidAccount(account) {
		return errors.New("invalid accountUuid for credential storage")
	}
	line, err := interactiveLine(account, service, blob)
	if err != nil {
		return err
	}
	return checkLine(line, service)
}

func interactiveLine(account, service string, blob []byte) (string, error) {
	if account == "" || service == "" || strings.ContainsAny(account+service, "\r\n\x00") {
		return "", errors.New("invalid Keychain account or service")
	}
	// F1: security's interactive parser requires quoted, escaped values for every option.
	quote := func(value string) string {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
	}
	return "add-generic-password -U -a " + quote(account) + " -s " + quote(service) + " -X " + quote(hex.EncodeToString(blob)) + "\n", nil
}

func checkLine(line, service string) error {
	// F1: security -i has a 4096-byte buffer; backups never use argv.
	if len(line) > 4032 {
		return fmt.Errorf("credentials exceed Keychain interactive line limit (4032 bytes) for service %q", service)
	}
	return nil
}

func (k Keychain) writeLine(line, service string) error {
	cmd, cancel := k.command("-i")
	defer cancel()
	cmd.Stdin = bytes.NewBufferString(line)
	cmd.Stdout = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cannot write Keychain service %q", service)
	}
	return nil
}

func (k Keychain) WriteLive(account, service string, blob []byte) error {
	line, err := interactiveLine(account, service, blob)
	if err != nil {
		return err
	}
	if len(line) <= 4032 {
		return k.writeLine(line, service)
	}
	// F1: the user approved Claude Code's argv fallback for the LIVE item only.
	cmd, cancel := k.command("add-generic-password", "-U", "-a", account, "-s", service, "-X", hex.EncodeToString(blob))
	defer cancel()
	cmd.Stdout = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cannot write Keychain service %q", service)
	}
	return nil
}

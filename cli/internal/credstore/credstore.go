// Package credstore stores account backups in Keychain or private files.
package credstore

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"fasthands/internal/statehome"
)

var ErrAbsent = errors.New("Keychain item absent")

// Bound OS prompt waits; a locked or stalled Keychain must remain unreadable.
var securityTimeout = 10 * time.Second

type Backend interface {
	Kind() string
	Write(account string, blob []byte) error
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

func (f Files) Write(account string, blob []byte) error {
	if !ValidAccount(account) {
		return errors.New("invalid accountUuid for credential storage")
	}
	path := filepath.Join(f.Directory, account+".json")
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

func (k Keychain) Read(account, service string) ([]byte, error) {
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
	if !ValidAccount(account) {
		return errors.New("invalid accountUuid for credential storage")
	}
	// security's interactive parser accepts quoted identifiers; reject line injection above.
	quoted := account
	if strings.ContainsAny(account, " \t\"'") {
		quoted = `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(account) + `"`
	}
	line := "add-generic-password -U -a " + quoted + " -s fasthands -X " + hex.EncodeToString(blob) + "\n"
	// security -i has a 4096-byte line buffer. Keep the agreed 4032-byte ceiling.
	if len(line) > 4032 {
		return errors.New("credentials exceed Keychain interactive line limit (4032 bytes) for service fasthands")
	}
	cmd, cancel := k.command("-i")
	defer cancel()
	cmd.Stdin = bytes.NewBufferString(line)
	cmd.Stdout = io.Discard
	if err := cmd.Run(); err != nil {
		return errors.New("cannot write Keychain service fasthands")
	}
	return nil
}

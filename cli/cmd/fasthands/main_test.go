package main

import (
	"bytes"
	"errors"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestMainHelp(t *testing.T) {
	bin := buildBin(t)
	for _, spelling := range []string{"-h", "--help", "help"} {
		t.Run(spelling, func(t *testing.T) {
			cmd := exec.Command(bin, spelling)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("help must exit 0: %v (stderr=%q)", err, stderr.String())
			}
			if stdout.Len() == 0 {
				t.Fatalf("help must print to stdout (stderr=%q)", stderr.String())
			}
		})
	}
}

func TestMainUnknownArgument(t *testing.T) {
	bin := buildBin(t)
	cmd := exec.Command(bin, "definitely-not-a-command")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if err == nil || !errors.As(err, &exitErr) {
		t.Fatalf("an unrecognized argument must exit non-zero: %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("an unrecognized argument must not write stdout: %q", stdout.String())
	}
	if stderr.Len() == 0 {
		t.Fatalf("an unrecognized argument must print a usage message to stderr")
	}
}

func buildBin(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "bin")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return bin
}

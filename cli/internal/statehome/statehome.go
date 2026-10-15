// Package statehome locates fasthands data and writes private, durable files.
package statehome

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type Paths struct {
	State       string
	Credentials string
}

func Locate() (Paths, error) {
	if home := os.Getenv("FASTHANDS_HOME"); home != "" {
		return Paths{filepath.Join(home, "state"), filepath.Join(home, "credentials")}, nil
	}
	state := os.Getenv("XDG_STATE_HOME")
	data := os.Getenv("XDG_DATA_HOME")
	if state == "" || data == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return Paths{}, fmt.Errorf("cannot locate home directory")
		}
		if state == "" {
			state = filepath.Join(home, ".local", "state")
		}
		if data == "" {
			data = filepath.Join(home, ".local", "share")
		}
	}
	return Paths{filepath.Join(state, "fasthands"), filepath.Join(data, "fasthands", "credentials")}, nil
}

func PrivateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return os.Chmod(path, 0700)
}

// The operations stay together so tests can inject failures at each durability boundary.
type writeOps struct {
	open   func(string, int, os.FileMode) (*os.File, error)
	sync   func(*os.File) error
	rename func(string, string) error
}

func AtomicWrite(path string, data []byte) error {
	return atomicWrite(path, data, writeOps{os.OpenFile, (*os.File).Sync, os.Rename})
}

func atomicWrite(path string, data []byte, ops writeOps) error {
	dir := filepath.Dir(path)
	if err := PrivateDir(dir); err != nil {
		return err
	}
	return replace(path, data, 0600, ops)
}

// ReplaceFile writes Claude's files without changing their parent directories (F2, F3).
func ReplaceFile(path string, data []byte) error {
	return replaceFile(path, data, writeOps{os.OpenFile, (*os.File).Sync, os.Rename})
}

func replaceFile(path string, data []byte, ops writeOps) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		// A dangling symlink is not an absent file; never replace the link itself.
		if _, linkErr := os.Lstat(path); !errors.Is(linkErr, os.ErrNotExist) {
			return err
		}
		resolved = path
	}
	mode := os.FileMode(0600)
	info, err := os.Stat(resolved)
	if err == nil {
		mode = info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return replace(resolved, data, mode, ops)
}

func replace(path string, data []byte, mode os.FileMode, ops writeOps) error {
	dir := filepath.Dir(path)
	temp := filepath.Join(dir, ".fasthands-"+rand.Text()+".tmp")
	f, err := ops.open(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer os.Remove(temp)
	defer f.Close()
	// Preserve the target's exact mode even under a restrictive caller umask.
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := ops.sync(f); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := ops.rename(temp, path); err != nil {
		return err
	}
	// Persist the rename as well as the contents before reporting success.
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return ops.sync(d)
}

// Package statehome locates fasthands data and writes private, durable files.
package statehome

import (
	"crypto/rand"
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
	temp := filepath.Join(dir, ".fasthands-"+rand.Text()+".tmp")
	f, err := ops.open(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer os.Remove(temp)
	defer f.Close()
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

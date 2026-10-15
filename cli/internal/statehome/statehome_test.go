package statehome

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

func TestLocate(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("FASTHANDS_HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	tests := []struct {
		name, override, state, data string
		want                        Paths
	}{
		{"default", "", "", "", Paths{filepath.Join(home, ".local/state/fasthands"), filepath.Join(home, ".local/share/fasthands/credentials")}},
		{"xdg", "", filepath.Join(home, "state"), filepath.Join(home, "data"), Paths{filepath.Join(home, "state/fasthands"), filepath.Join(home, "data/fasthands/credentials")}},
		{"override", filepath.Join(home, "fh"), "/ignored-state", "/ignored-data", Paths{filepath.Join(home, "fh/state"), filepath.Join(home, "fh/credentials")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("FASTHANDS_HOME", tt.override)
			t.Setenv("XDG_STATE_HOME", tt.state)
			t.Setenv("XDG_DATA_HOME", tt.data)
			got, err := Locate()
			if err != nil || got != tt.want {
				t.Fatalf("wrong paths: %v, %v", got, err)
			}
		})
	}
}

func TestLocateWithoutHome(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("FASTHANDS_HOME", "")
	t.Setenv("XDG_STATE_HOME", "/state")
	t.Setenv("XDG_DATA_HOME", "/data")
	got, err := Locate()
	if err != nil || got != (Paths{State: "/state/fasthands", Credentials: "/data/fasthands/credentials"}) {
		t.Fatal("XDG paths must not require HOME")
	}
	t.Setenv("FASTHANDS_HOME", "/override")
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	if _, err := Locate(); err != nil {
		t.Fatal("FASTHANDS_HOME must override HOME and XDG")
	}
}

func TestAtomicWritePrivateFromCreation(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	root := t.TempDir()
	dir := filepath.Join(root, "new", "credentials")
	path := filepath.Join(dir, "account.json")
	ops := writeOps{
		open: func(name string, flags int, mode os.FileMode) (*os.File, error) {
			if flags&os.O_CREATE == 0 || flags&os.O_EXCL == 0 || mode != 0600 {
				t.Fatal("temporary file must be exclusive and private at creation")
			}
			checkMode(t, filepath.Dir(dir), 0700)
			checkMode(t, dir, 0700)
			f, err := os.OpenFile(name, flags, mode)
			if err == nil {
				checkMode(t, name, 0600)
			}
			return f, err
		},
		sync:   (*os.File).Sync,
		rename: os.Rename,
	}
	if err := atomicWrite(path, []byte("first"), ops); err != nil {
		t.Fatal(err)
	}
	checkMode(t, path, 0600)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(path, []byte("second")); err != nil {
		t.Fatal(err)
	}
	checkMode(t, path, 0600)
	assertOnlyTarget(t, dir)
}

func TestAtomicWriteDurabilityAndCleanup(t *testing.T) {
	for _, failure := range []string{"none", "open", "write", "file-sync", "rename", "dir-sync"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "account.json")
			if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
				t.Fatal(err)
			}
			var events []string
			fail := errors.New("injected failure")
			ops := writeOps{
				open: func(name string, flags int, mode os.FileMode) (*os.File, error) {
					events = append(events, "open")
					if filepath.Dir(name) != dir {
						t.Fatal("temporary file must share target directory")
					}
					if failure == "open" {
						return nil, fail
					}
					if failure == "write" {
						flags = os.O_CREATE | os.O_EXCL | os.O_RDONLY
					}
					return os.OpenFile(name, flags, mode)
				},
				sync: func(f *os.File) error {
					event := "file-sync"
					if f.Name() == dir {
						event = "dir-sync"
					} else {
						data, err := os.ReadFile(f.Name())
						if err != nil || string(data) != "new" {
							t.Fatal("contents must be written before file sync")
						}
					}
					events = append(events, event)
					if failure == event {
						return fail
					}
					return f.Sync()
				},
				rename: func(from, to string) error {
					events = append(events, "rename")
					if failure == "rename" {
						return fail
					}
					return os.Rename(from, to)
				},
			}
			err := atomicWrite(path, []byte("new"), ops)
			if (failure == "none") != (err == nil) {
				t.Fatalf("unexpected failure result: %v", err)
			}
			if failure == "none" && !reflect.DeepEqual(events, []string{"open", "file-sync", "rename", "dir-sync"}) {
				t.Fatalf("wrong durability order: %v", events)
			}
			want := "old"
			if failure == "none" || failure == "dir-sync" {
				want = "new"
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil || string(data) != want {
				t.Fatal("wrong target after failure")
			}
			assertOnlyTarget(t, dir)
		})
	}
}

func checkMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != want {
		t.Fatalf("wrong mode for %s", path)
	}
}

func assertOnlyTarget(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "account.json" {
		t.Fatal("temporary file left behind")
	}
}

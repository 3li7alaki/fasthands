package claudelock

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"fasthands/internal/claudecfg"
)

func locations(t *testing.T) claudecfg.Locations {
	t.Helper()
	root := t.TempDir()
	storage := filepath.Join(root, "storage")
	if err := os.Mkdir(storage, 0700); err != nil {
		t.Fatal(err)
	}
	return claudecfg.Locations{StorageDir: storage, GlobalConfig: filepath.Join(root, "global.json")}
}

func held(t *testing.T, locks []Lock) *Held {
	t.Helper()
	h, err := Acquire(locks, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Release() })
	return h
}

func shortIntervals(t *testing.T) {
	t.Helper()
	oldTouch, oldRetry := touchInterval, retryJitter
	touchInterval = 20 * time.Millisecond
	retryJitter = func() time.Duration { return 5 * time.Millisecond }
	t.Cleanup(func() { touchInterval, retryJitter = oldTouch, oldRetry })
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
}

func age(t *testing.T, path string, age time.Duration) os.FileInfo {
	t.Helper()
	old := time.Now().Add(-age)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	return stat(t, path)
}

func stat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func absent(t *testing.T, locks []Lock) {
	t.Helper()
	for _, lock := range locks {
		if _, err := os.Stat(lock.Path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("lock left behind at %q", lock.Path)
		}
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(300 * time.Millisecond)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("lock update did not arrive")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestLocksAndRelease(t *testing.T) {
	for _, mode := range []string{"direct", "symlink", "relative"} {
		t.Run(mode, func(t *testing.T) {
			loc := locations(t)
			target, err := filepath.EvalSymlinks(loc.StorageDir)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "symlink" {
				link := filepath.Join(filepath.Dir(loc.StorageDir), "link")
				if err := os.Symlink(loc.StorageDir, link); err != nil {
					t.Fatal(err)
				}
				loc.StorageDir = link
			} else if mode == "relative" {
				t.Chdir(filepath.Dir(loc.StorageDir))
				loc.StorageDir, loc.GlobalConfig = "storage", "./global.json"
			}
			want := []Lock{
				{filepath.Join(loc.StorageDir, ".oauth_refresh.lock"), 60 * time.Second},
				{target + ".lock", 60 * time.Second},
				{filepath.Join(loc.StorageDir, ".storage-write"), 15 * time.Second},
				{loc.GlobalConfig + ".lock", 10 * time.Second},
			}
			locks := Locks(loc)
			if !reflect.DeepEqual(locks, want) {
				t.Fatalf("wrong lock locations or stale windows: %v", locks)
			}
			h := held(t, locks)
			for _, lock := range locks {
				info := stat(t, lock.Path)
				if !info.IsDir() || info.Mode().Perm() != 0700 {
					t.Fatal("lock must be a private directory")
				}
			}
			entries, err := os.ReadDir(loc.StorageDir)
			if err != nil || len(entries) != 2 {
				t.Fatal("acquisition must create only refresh and storage-write inside storage")
			}
			if h.Lost() != nil || h.Release() != nil || h.Release() != nil || h.Lost() != nil {
				t.Fatal("clean release must be idempotent")
			}
			absent(t, locks)
		})
	}
}

func TestLocksRealpathFailure(t *testing.T) {
	loc := claudecfg.Locations{StorageDir: filepath.Join(t.TempDir(), "absent"), GlobalConfig: "/config"}
	if got := Locks(loc)[1].Path; got != loc.StorageDir+".lock" {
		t.Fatal("failed realpath must use original storage path")
	}
}

func TestAcquireBusyPreservesHolder(t *testing.T) {
	shortIntervals(t)
	locks := Locks(locations(t))
	h := held(t, locks)
	before := make([]os.FileInfo, len(locks))
	for i, lock := range locks {
		before[i] = stat(t, lock.Path)
	}
	start := time.Now()
	other, err := Acquire(locks, 35*time.Millisecond)
	if other != nil || !errors.Is(err, ErrBusy) || !strings.Contains(err.Error(), locks[0].Path) {
		t.Fatal("contending acquisition must return ErrBusy naming the lock")
	}
	if elapsed := time.Since(start); elapsed < 35*time.Millisecond || elapsed > time.Second {
		t.Fatal("busy acquisition must respect its timeout")
	}
	for i, lock := range locks {
		if !os.SameFile(before[i], stat(t, lock.Path)) {
			t.Fatal("waiter removed the first holder's lock")
		}
	}
	if err := h.Lost(); err != nil {
		t.Fatal(err)
	}
}

func TestStaleWindows(t *testing.T) {
	for _, tt := range []struct {
		name  string
		index int
		age   time.Duration
		stale bool
	}{
		{"refresh-stale", 0, 61 * time.Second, true}, {"refresh-live", 0, 59 * time.Second, false},
		{"legacy-stale", 1, 61 * time.Second, true}, {"legacy-live", 1, 59 * time.Second, false},
		{"storage-stale", 2, 16 * time.Second, true}, {"storage-live", 2, 14 * time.Second, false},
		{"config-stale", 3, 11 * time.Second, true}, {"config-live", 3, 9 * time.Second, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			locks := Locks(locations(t))
			path := locks[tt.index].Path
			mkdir(t, path)
			before := age(t, path, tt.age)
			h, err := Acquire(locks, 0)
			if tt.stale {
				if err != nil || h == nil {
					t.Fatalf("stale lock was not taken: %v", err)
				}
				t.Cleanup(func() { _ = h.Release() })
				if !stat(t, path).ModTime().After(before.ModTime()) {
					t.Fatal("stale directory was not replaced")
				}
				if err := h.Release(); err != nil {
					t.Fatal(err)
				}
				absent(t, locks)
			} else {
				if h != nil || !errors.Is(err, ErrBusy) {
					t.Fatal("live lock must remain busy")
				}
				after := stat(t, path)
				if !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) {
					t.Fatal("waiter changed live lock")
				}
				absent(t, append(locks[:tt.index:tt.index], locks[tt.index+1:]...))
			}
		})
	}
}

func TestAcquireRollsBackBeforeWaiting(t *testing.T) {
	shortIntervals(t)
	locks := Locks(locations(t))
	mkdir(t, locks[3].Path)
	waits := 0
	retryJitter = func() time.Duration {
		absent(t, locks[:3])
		waits++
		return 5 * time.Millisecond
	}
	h, err := Acquire(locks, 25*time.Millisecond)
	if h != nil || !errors.Is(err, ErrBusy) || !strings.Contains(err.Error(), locks[3].Path) || waits == 0 {
		t.Fatal("busy config lock must cause rollback and retry")
	}
	absent(t, locks[:3])
	stat(t, locks[3].Path)
}

func TestAcquireRetriesAfterRollback(t *testing.T) {
	shortIntervals(t)
	locks := Locks(locations(t))
	mkdir(t, locks[3].Path)
	retryJitter = func() time.Duration {
		absent(t, locks[:3])
		if err := os.Remove(locks[3].Path); err != nil {
			t.Fatal(err)
		}
		return time.Millisecond
	}
	h, err := Acquire(locks, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Release() })
	if err := h.Release(); err != nil {
		t.Fatal(err)
	}
	absent(t, locks)
}

func TestTouchAdvancesEveryLock(t *testing.T) {
	shortIntervals(t)
	locks := Locks(locations(t))
	h := held(t, locks)
	before := make([]time.Time, len(locks))
	for i, lock := range locks {
		before[i] = stat(t, lock.Path).ModTime()
	}
	waitFor(t, func() bool {
		for i, lock := range locks {
			if !stat(t, lock.Path).ModTime().After(before[i]) {
				return false
			}
		}
		return true
	})
	if h.Lost() != nil || h.Release() != nil {
		t.Fatal("own refresh must not count as loss")
	}
}

func TestLostStopsTouchingAndReleaseReportsIt(t *testing.T) {
	for _, change := range []string{"remove", "mtime", "replace"} {
		t.Run(change, func(t *testing.T) {
			shortIntervals(t)
			locks := Locks(locations(t))
			h := held(t, locks)
			path := locks[0].Path
			original := stat(t, path)
			old := time.Unix(1, 0)
			switch change {
			case "remove":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "mtime":
				if err := os.Chtimes(path, old, old); err != nil {
					t.Fatal(err)
				}
			case "replace":
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				mkdir(t, path)
				if err := os.Chtimes(path, original.ModTime(), original.ModTime()); err != nil {
					t.Fatal(err)
				}
			}
			waitFor(t, func() bool {
				h.mu.Lock()
				defer h.mu.Unlock()
				return h.locks[0].lost != nil
			})
			if err := h.Lost(); err == nil || !strings.Contains(err.Error(), path) {
				t.Fatal("Lost must report the changed lock path")
			}
			before := stat(t, locks[2].Path).ModTime()
			waitFor(t, func() bool { return stat(t, locks[2].Path).ModTime().After(before) })
			if change == "mtime" && !stat(t, path).ModTime().Equal(old) {
				t.Fatal("lost lock must stop refreshing")
			}
			if err := h.Release(); err == nil || !strings.Contains(err.Error(), path) {
				t.Fatal("release must report lost ownership")
			}
			if h.Release() == nil || h.Lost() == nil {
				t.Fatal("ownership loss must remain recorded")
			}
			absent(t, locks[1:])
			if change == "replace" {
				stat(t, path)
			} else {
				absent(t, locks[:1])
			}
		})
	}
}

func TestLostChecksBeforeWrite(t *testing.T) {
	locks := Locks(locations(t))
	h := held(t, locks)
	if err := os.Remove(locks[0].Path); err != nil {
		t.Fatal(err)
	}
	if h.Lost() == nil || h.Release() == nil {
		t.Fatal("loss before the next refresh must still be reported")
	}
}

func TestAcquisitionErrorsPreservePathsAndContents(t *testing.T) {
	for _, kind := range []string{"file", "nonempty-stale", "missing-parent"} {
		t.Run(kind, func(t *testing.T) {
			locks := Locks(locations(t))
			path := locks[3].Path
			content := []byte(`{"accessToken":"lock-access-private","refreshToken":"lock-refresh-private"}`)
			var keep string
			switch kind {
			case "file":
				keep = path
			case "nonempty-stale":
				mkdir(t, path)
				keep = filepath.Join(path, "content")
			case "missing-parent":
				path = filepath.Join(filepath.Dir(path), "absent", "config.lock")
				locks[3].Path = path
			}
			if keep != "" {
				if err := os.WriteFile(keep, content, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "nonempty-stale" {
				age(t, path, time.Minute)
			}
			h, err := Acquire(locks, 0)
			if h != nil || err == nil || errors.Is(err, ErrBusy) || !strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "private") {
				t.Fatal("invalid lock must fail with a safe path error")
			}
			absent(t, locks[:3])
			if keep != "" {
				data, err := os.ReadFile(keep)
				if err != nil || !bytes.Equal(data, content) {
					t.Fatal("lock error removed or changed existing contents")
				}
			} else if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("acquisition created a missing parent")
			}
		})
	}
}

func TestOwnerRecordUntouched(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(map[bool]string{false: "free", true: "stale"}[stale], func(t *testing.T) {
			loc := locations(t)
			path := filepath.Join(loc.StorageDir, ".oauth_refresh.lock.owner")
			content := []byte("{\"lockBirthtimeMs\":123,\"pid\":456}\n")
			if err := os.WriteFile(path, content, 0600); err != nil {
				t.Fatal(err)
			}
			before := stat(t, path)
			locks := Locks(loc)
			if stale {
				mkdir(t, locks[0].Path)
				age(t, locks[0].Path, 61*time.Second)
			}
			h := held(t, locks)
			check := func() {
				data, err := os.ReadFile(path)
				after := stat(t, path)
				if err != nil || !bytes.Equal(data, content) || !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) {
					t.Fatal("refresh owner record changed")
				}
			}
			check()
			if err := h.Release(); err != nil {
				t.Fatal(err)
			}
			check()
		})
	}
}

func TestReleaseReverseOrder(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "parent.lock")
	locks := []Lock{{parent, time.Minute}, {filepath.Join(parent, "child.lock"), time.Minute}}
	h := held(t, locks)
	// Nested child operations change the parent's mtime, but cleanup must still run in reverse.
	if err := h.Release(); err == nil || !strings.Contains(err.Error(), parent) || strings.Contains(err.Error(), "cannot remove") {
		t.Fatal("nested cleanup must report parent mtime loss without a removal failure")
	}
	absent(t, locks)
}

func TestReleaseFailurePreservesContents(t *testing.T) {
	locks := Locks(locations(t))
	h := held(t, locks)
	path := filepath.Join(locks[0].Path, "content")
	content := []byte("lock-access-private-lock-refresh-private")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	err := h.Release()
	if err == nil || !strings.Contains(err.Error(), locks[0].Path) || !strings.Contains(err.Error(), "cannot remove") || strings.Contains(err.Error(), "private") {
		t.Fatal("release failure must name lock without quoting its contents")
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, content) {
		t.Fatal("release must not remove contents")
	}
	absent(t, locks[1:])
}

func TestConcurrentLostAndRelease(t *testing.T) {
	shortIntervals(t)
	locks := Locks(locations(t))
	h := held(t, locks)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if err := h.Lost(); err != nil {
				t.Error(err)
			}
			if err := h.Release(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	absent(t, locks)
}

func TestRetryJitterBounds(t *testing.T) {
	for range 100 {
		if delay := retryJitter(); delay < 250*time.Millisecond || delay > 500*time.Millisecond {
			t.Fatal("retry jitter must stay between 250 and 500ms")
		}
	}
}

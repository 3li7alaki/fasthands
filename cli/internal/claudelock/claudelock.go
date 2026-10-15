// Package claudelock cooperates with Claude Code's directory locks.
package claudelock

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync"
	"time"

	"fasthands/internal/claudecfg"
)

type Lock struct {
	Path  string
	Stale time.Duration
}

var ErrBusy = errors.New("Claude Code lock busy")

// L8: refresh well below half the shortest (10s) stale window.
var touchInterval = 2 * time.Second

// L7: jitter retries so competing mkdir waiters do not stay in step.
var retryJitter = func() time.Duration {
	return 250*time.Millisecond + time.Duration(rand.Int64N(int64(250*time.Millisecond)))
}

// Locks returns the refresh, legacy, storage-write, and config locks in L8 order.
func Locks(loc claudecfg.Locations) []Lock {
	legacy, err := filepath.Abs(loc.StorageDir)
	if err == nil {
		legacy, err = filepath.EvalSymlinks(legacy)
	}
	if err != nil {
		legacy = loc.StorageDir
	}
	// L8: Claude Code gives these locks distinct stale windows.
	return []Lock{
		{filepath.Join(loc.StorageDir, ".oauth_refresh.lock"), 60 * time.Second},
		{legacy + ".lock", 60 * time.Second},
		{filepath.Join(loc.StorageDir, ".storage-write"), 15 * time.Second},
		{loc.GlobalConfig + ".lock", 10 * time.Second},
	}
}

type heldLock struct {
	path string
	info os.FileInfo
	lost error
}

type Held struct {
	mu         sync.Mutex
	locks      []heldLock
	stop       chan struct{}
	done       chan struct{}
	once       sync.Once
	released   bool
	releaseErr error
}

// Acquire takes every lock or none, rolling back before waiting for contention.
func Acquire(locks []Lock, timeout time.Duration) (*Held, error) {
	deadline := time.Now().Add(timeout)
	for {
		var taken []heldLock
		var err error
		for _, lock := range locks {
			var entry heldLock
			entry, err = take(lock)
			if err != nil {
				break
			}
			taken = append(taken, entry)
		}
		if err == nil {
			h := &Held{locks: taken, stop: make(chan struct{}), done: make(chan struct{})}
			go h.refresh(touchInterval)
			return h, nil
		}
		if releaseErr := removeLocks(taken); releaseErr != nil {
			return nil, errors.Join(err, releaseErr)
		}
		if !errors.Is(err, ErrBusy) || time.Until(deadline) <= 0 {
			return nil, err
		}
		time.Sleep(min(retryJitter(), time.Until(deadline)))
		if time.Until(deadline) <= 0 {
			return nil, err
		}
	}
}

func take(lock Lock) (heldLock, error) {
	err := os.Mkdir(lock.Path, 0700)
	if errors.Is(err, os.ErrExist) {
		info, statErr := os.Stat(lock.Path)
		if errors.Is(statErr, os.ErrNotExist) {
			return heldLock{}, fmt.Errorf("%w at %q", ErrBusy, lock.Path)
		}
		if statErr != nil || !info.IsDir() {
			return heldLock{}, fmt.Errorf("cannot inspect Claude Code lock at %q", lock.Path)
		}
		if !info.ModTime().Before(time.Now().Add(-lock.Stale)) {
			return heldLock{}, fmt.Errorf("%w at %q", ErrBusy, lock.Path)
		}
		// L7: rmdir refuses non-empty directories; never remove their contents.
		if err := os.Remove(lock.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return heldLock{}, fmt.Errorf("cannot remove stale Claude Code lock at %q", lock.Path)
		}
		err = os.Mkdir(lock.Path, 0700)
	}
	if errors.Is(err, os.ErrExist) {
		return heldLock{}, fmt.Errorf("%w at %q", ErrBusy, lock.Path)
	}
	if err != nil {
		return heldLock{}, fmt.Errorf("cannot acquire Claude Code lock at %q", lock.Path)
	}
	info, err := os.Stat(lock.Path)
	if err != nil {
		var removeErr error
		if os.Remove(lock.Path) != nil {
			removeErr = fmt.Errorf("cannot remove Claude Code lock at %q", lock.Path)
		}
		return heldLock{}, errors.Join(fmt.Errorf("cannot inspect Claude Code lock at %q", lock.Path), removeErr)
	}
	return heldLock{path: lock.Path, info: info}, nil
}

func (lock *heldLock) inspect() os.FileInfo {
	info, err := os.Stat(lock.path)
	if lock.lost == nil && (err != nil || !info.IsDir() ||
		!os.SameFile(info, lock.info) || !info.ModTime().Equal(lock.info.ModTime())) {
		lock.lost = fmt.Errorf("lost Claude Code lock at %q", lock.path)
	}
	return info
}

func (h *Held) refresh(interval time.Duration) {
	defer close(h.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-h.stop:
			return
		case <-ticker.C:
			h.mu.Lock()
			for i := range h.locks {
				lock := &h.locks[i]
				if lock.lost != nil {
					continue
				}
				lock.inspect()
				if lock.lost != nil {
					continue
				}
				now := time.Now()
				if os.Chtimes(lock.path, now, now) != nil {
					lock.lost = fmt.Errorf("cannot refresh Claude Code lock at %q", lock.path)
					continue
				}
				info, err := os.Stat(lock.path)
				if err != nil || !info.IsDir() || !os.SameFile(info, lock.info) {
					lock.lost = fmt.Errorf("lost Claude Code lock at %q", lock.path)
					continue
				}
				lock.info = info
			}
			h.mu.Unlock()
		}
	}
}

// Lost also checks immediately, so callers can detect loss before a write.
func (h *Held) Lost() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	var errs []error
	for i := range h.locks {
		if !h.released {
			h.locks[i].inspect()
		}
		errs = append(errs, h.locks[i].lost)
	}
	return errors.Join(errs...)
}

func removeLocks(locks []heldLock) error {
	var errs []error
	for i := len(locks) - 1; i >= 0; i-- {
		lock := &locks[i]
		info := lock.inspect()
		errs = append(errs, lock.lost)
		// An inode replacement belongs to another holder, even if its mtime matches.
		if info != nil && info.IsDir() && os.SameFile(info, lock.info) {
			if os.Remove(lock.path) != nil {
				errs = append(errs, fmt.Errorf("cannot remove Claude Code lock at %q", lock.path))
			}
		}
	}
	return errors.Join(errs...)
}

// Release stops refreshing and removes owned directories in reverse order, once.
func (h *Held) Release() error {
	h.once.Do(func() {
		close(h.stop)
		<-h.done
		h.mu.Lock()
		defer h.mu.Unlock()
		h.releaseErr = removeLocks(h.locks)
		h.released = true
	})
	return h.releaseErr
}

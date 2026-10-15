// Package claudesessions reads Claude Code's live session records.
package claudesessions

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Session struct {
	PID        int    `json:"pid"`
	Status     string `json:"status"`
	CWD        string `json:"cwd"`
	Kind       string `json:"kind"`
	Path       string `json:"path"`
	Unreadable bool   `json:"unreadable,omitempty"`
}

var processProbe = struct {
	alive func(int) bool
	start func(int, bool) (string, error)
}{processAlive, processStart}

func digits(value string) bool {
	return value != "" && strings.Trim(value, "0123456789") == ""
}

// Scan returns live sessions; an absent sessions directory is empty (S1).
func Scan(configHome string) ([]Session, error) {
	dir := filepath.Join(configHome, "sessions")
	f, err := os.Open(dir)
	if errors.Is(err, os.ErrNotExist) {
		return []Session{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read Claude Code sessions at %q", dir)
	}
	defer f.Close()
	// S1: read names only; ReadDir may stat entries with an unknown directory type.
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("cannot read Claude Code sessions at %q", dir)
	}
	sort.Strings(names)
	sessions := []Session{}
	for _, name := range names {
		// S1: filter names before any file I/O, especially session key files.
		if !strings.HasSuffix(name, ".json") || !digits(strings.TrimSuffix(name, ".json")) {
			continue
		}
		path := filepath.Join(dir, name)
		var record *struct {
			PID       int    `json:"pid"`
			ProcStart string `json:"procStart"`
			Status    string `json:"status"`
			CWD       string `json:"cwd"`
			Kind      string `json:"kind"`
		}
		data, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(data, &record) != nil || record == nil {
			// S5: unknown record contents must block a switch, even without a pid.
			sessions = append(sessions, Session{Path: path, Unreadable: true})
			continue
		}
		if record.PID <= 1 || !processProbe.alive(record.PID) || !sameProcess(record.PID, record.ProcStart) {
			continue
		}
		sessions = append(sessions, Session{PID: record.PID, Status: record.Status, CWD: record.CWD, Kind: record.Kind, Path: path})
	}
	return sessions, nil
}

func MidTurn(sessions []Session) []Session {
	mid := []Session{}
	for _, session := range sessions {
		// S3, S5: only known safe states permit switching.
		if session.Unreadable || session.Status != "idle" && session.Status != "shell" {
			mid = append(mid, session)
		}
	}
	return mid
}

func sameProcess(pid int, recorded string) bool {
	ticks := digits(recorded)
	live, err := processProbe.start(pid, ticks)
	if err != nil {
		return true
	}
	if ticks {
		return !digits(live) || live == recorded
	}
	old, oldErr := parseStart(recorded)
	now, liveErr := parseStart(live)
	// S4: unknown starts stay live; wall-clock starts allow 120s of clock-step slack.
	return oldErr != nil || liveErr != nil || now.Sub(old) <= 120*time.Second
}

func processAlive(pid int) bool {
	if pid <= 1 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func processStart(pid int, ticks bool) (string, error) {
	if ticks {
		data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if err != nil {
			return "", err
		}
		return parseStat(string(data))
	}
	cmd := exec.Command("ps", "-o", "lstart=", "-p", strconv.Itoa(pid))
	cmd.Env = append(os.Environ(), "LC_ALL=C", "TZ=UTC")
	data, err := cmd.Output()
	return strings.TrimSpace(string(data)), err
}

func parseStat(stat string) (string, error) {
	// S4: comm may contain spaces and ')'; field 22 is index 19 after the last ')'.
	end := strings.LastIndexByte(stat, ')')
	if end >= 0 {
		fields := strings.Fields(stat[end+1:])
		if len(fields) > 19 && digits(fields[19]) {
			return fields[19], nil
		}
	}
	return "", errors.New("invalid process stat")
}

func parseStart(start string) (time.Time, error) {
	// S4: whitespace splitting handles ps's space-padded single-digit days.
	return time.ParseInLocation("Mon Jan 2 15:04:05 2006", strings.Join(strings.Fields(start), " "), time.UTC)
}

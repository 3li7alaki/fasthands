package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"fasthands/internal/accounts"
	"fasthands/internal/picker"
	"fasthands/internal/statehome"
	usageState "fasthands/internal/usage"
)

var spawnAuto = func() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	_, err = startDetached(executable, "auto", "--once")
	return err
}

func startDetached(executable string, args ...string) (int, error) {
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return 0, err
	}
	defer null.Close()
	cmd := exec.Command(executable, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = null, null, null
	// A new session survives Claude terminating the status line's process group.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	return pid, cmd.Process.Release()
}

func autoEnabled(directory string) bool {
	_, err := os.Stat(filepath.Join(directory, "auto.disabled"))
	return os.IsNotExist(err)
}

func autoState(directory, action string, jsonMode bool, stdout, stderr io.Writer) int {
	path := filepath.Join(directory, "auto.disabled")
	var err error
	switch action {
	case "off":
		err = statehome.AtomicWrite(path, nil)
	case "on":
		err = os.Remove(path)
		if os.IsNotExist(err) {
			err = nil
		}
	}
	if err != nil {
		fmt.Fprintf(stderr, "cannot change auto switching state at %q\n", path)
		return 1
	}
	enabled := autoEnabled(directory)
	if jsonMode {
		return outputJSON(stdout, stderr, struct {
			Auto bool `json:"auto"`
		}{enabled})
	}
	state := "off"
	if enabled {
		state = "on"
	}
	fmt.Fprintln(stdout, "auto switching "+state)
	return 0
}

func triggerAuto(directory string, list []picker.Account, live string) {
	// All trigger failures stay silent so automatic switching cannot break Claude's display.
	if !autoEnabled(directory) {
		return
	}
	state, err := (usageState.Store{Directory: directory}).Read()
	if err != nil {
		return
	}
	// Reuse Pickable's metadata snapshot, but decide on usage recorded by this hook.
	for i := range list {
		list[i].Windows = state.Accounts[list[i].ID].Windows
	}
	if picker.Decide(list, live, state.LastSwitchAt, now().Unix()).Action != "switch" {
		return
	}
	// Serialize the debounce across sessions; release before the child takes auto.lock.
	lock, err := autoLock(directory)
	if err != nil || lock == nil {
		return
	}
	defer lock.Close()
	path, at := filepath.Join(directory, "auto.spawned"), now()
	if info, err := os.Stat(path); err == nil && at.Sub(info.ModTime()) < time.Minute {
		return
	}
	// Stamp before spawning: failed logins and spent budgets must also wait a minute.
	if statehome.AtomicWrite(path, nil) != nil || os.Chtimes(path, at, at) != nil {
		return
	}
	lock.Close()
	_ = spawnAuto()
}

type autoSwitch struct {
	At     int64  `json:"at"`
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason"`
}

func lastAutoSwitch(directory string) *autoSwitch {
	f, err := os.Open(filepath.Join(directory, "auto.log"))
	if err != nil {
		return nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil
	}
	return readLastAutoSwitch(f, info.Size())
}

func readLastAutoSwitch(log io.ReaderAt, size int64) *autoSwitch {
	// The append-only log grows forever; inspect at most its final 4 KiB.
	start := max(int64(0), size-4096)
	data, err := io.ReadAll(io.NewSectionReader(log, start, size-start))
	if err != nil {
		return nil
	}
	line := strings.TrimSuffix(string(data), "\n")
	i := strings.LastIndexByte(line, '\n')
	if i < 0 && start != 0 {
		return nil // The final line itself exceeds the read bound.
	}
	fields := strings.Split(line[i+1:], "\t")
	if len(fields) != 4 || !accounts.ValidAlias(fields[1]) || !accounts.ValidAlias(fields[2]) || fields[3] == "" {
		return nil
	}
	at, err := time.Parse(time.RFC3339, fields[0])
	if err != nil {
		return nil
	}
	return &autoSwitch{at.Unix(), fields[1], fields[2], fields[3]}
}

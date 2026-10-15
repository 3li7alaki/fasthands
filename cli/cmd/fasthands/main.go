package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"fasthands/internal/accounts"
	"fasthands/internal/base"
	"fasthands/internal/claudecfg"
	"fasthands/internal/claudelock"
	"fasthands/internal/credstore"
	"fasthands/internal/statehome"
	"fasthands/internal/version"
)

const usage = "usage: fasthands {add [--alias NAME] | ls | switch ALIAS} [--json]\n       fasthands [--version] [--help] [--json]"

var platform = runtime.GOOS
var securityPath = "/usr/bin/security"
var claudeLockTimeout = 10 * time.Second

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	switch base.Command(args) {
	case "help":
		fmt.Fprintln(stdout, usage)
		return 0
	case "version":
		if len(args) == 2 && args[1] == "--json" {
			return outputJSON(stdout, stderr, map[string]string{"version": version.Version})
		}
		fmt.Fprintln(stdout, version.Version)
		return 0
	}
	if len(args) == 0 {
		fmt.Fprintln(stdout, usage)
		return 0
	}
	if args[0] != "add" && args[0] != "ls" && args[0] != "switch" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {}
	jsonMode := fs.Bool("json", false, "print JSON")
	var alias string
	if args[0] == "add" {
		fs.StringVar(&alias, "alias", "", "account alias")
	}
	parseArgs := args[1:]
	if args[0] == "switch" && len(parseArgs) > 0 && !strings.HasPrefix(parseArgs[0], "-") {
		alias, parseArgs = parseArgs[0], parseArgs[1:]
	}
	if err := fs.Parse(parseArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stdout, usage)
			return 0
		}
		fmt.Fprintln(stderr, usage)
		return 2
	}
	aliasGiven := false
	fs.Visit(func(f *flag.Flag) { aliasGiven = aliasGiven || f.Name == "alias" })
	remaining := fs.NArg()
	if args[0] == "switch" && alias == "" && remaining == 1 {
		alias, remaining = fs.Arg(0), 0
	}
	if remaining != 0 || (aliasGiven || args[0] == "switch") && !accounts.ValidAlias(alias) {
		fmt.Fprintln(stderr, "invalid arguments or alias; alias must match ^[a-z0-9][a-z0-9_-]{0,31}$")
		return 2
	}
	paths, err := statehome.Locate()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	m := accounts.Manager{Paths: paths, Store: credstore.New(platform, securityPath, paths.Credentials)}
	if args[0] == "add" {
		// Capture both sources before creating fasthands state, backups, or metadata.
		capture, err := readActive()
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		result, err := m.Add(capture, alias, aliasGiven)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if *jsonMode {
			return outputJSON(stdout, stderr, result)
		}
		verb := "added"
		if result.Updated {
			verb = "updated"
		}
		fmt.Fprintf(stdout, "%s %s (%s)\n", verb, result.Alias, result.Email)
		return 0
	}
	if args[0] == "switch" {
		loc, err := claudecfg.Locate()
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		result, err := m.Switch(alias, loc, platform, securityPath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if *jsonMode {
			return outputJSON(stdout, stderr, result)
		}
		if !result.Switched {
			fmt.Fprintf(stdout, "%s is already active\n", alias)
			return 0
		}
		fmt.Fprintf(stdout, "switched to %s (%s)\n", alias, result.Email)
		if result.Store == "keychain" {
			fmt.Fprintln(stdout, "running Claude sessions pick it up within about 30 seconds")
		} else {
			fmt.Fprintln(stdout, "running Claude sessions pick it up on their next message")
		}
		for _, warning := range result.Warnings {
			fmt.Fprintln(stderr, "warning: "+warning)
		}
		return 0
	}
	list, err := m.List()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if *jsonMode {
		return outputJSON(stdout, stderr, struct {
			Accounts []accounts.Listed `json:"accounts"`
		}{list})
	}
	for _, account := range list {
		uuid := account.AccountUUID
		if len(uuid) > 8 {
			uuid = uuid[:8]
		}
		fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\n", account.Alias, account.Email, uuid, account.AddedAt, account.Store)
	}
	return 0
}

func readActive() (claudecfg.Capture, error) {
	loc, err := claudecfg.Locate()
	if err != nil {
		return claudecfg.Capture{}, err
	}
	held, err := claudelock.Acquire(claudelock.Locks(loc), claudeLockTimeout)
	if errors.Is(err, claudelock.ErrBusy) {
		return claudecfg.Capture{}, errors.New("Claude Code is busy with its credentials; retry in a few seconds")
	}
	if err != nil {
		return claudecfg.Capture{}, err
	}
	// Release before Add takes accounts.lock, avoiding the reverse of switch's lock order.
	defer held.Release()
	capture, err := claudecfg.Read(platform, securityPath)
	if err != nil {
		return claudecfg.Capture{}, err
	}
	if err := held.Lost(); err != nil {
		return claudecfg.Capture{}, errors.New("lost Claude Code credential lock; retry in a few seconds")
	}
	return capture, nil
}

func outputJSON(stdout, stderr io.Writer, value any) int {
	if err := json.NewEncoder(stdout).Encode(value); err != nil {
		fmt.Fprintln(stderr, "cannot write JSON output")
		return 1
	}
	return 0
}

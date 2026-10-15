package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

	"fasthands/internal/accounts"
	"fasthands/internal/base"
	"fasthands/internal/claudecfg"
	"fasthands/internal/credstore"
	"fasthands/internal/statehome"
	"fasthands/internal/version"
)

const usage = "usage: fasthands {add [--alias NAME] | ls} [--json]\n       fasthands [--version] [--help] [--json]"

var platform = runtime.GOOS
var securityPath = "/usr/bin/security"

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
	if args[0] != "add" && args[0] != "ls" {
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
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stdout, usage)
			return 0
		}
		fmt.Fprintln(stderr, usage)
		return 2
	}
	aliasGiven := false
	fs.Visit(func(f *flag.Flag) { aliasGiven = aliasGiven || f.Name == "alias" })
	if fs.NArg() != 0 || aliasGiven && !accounts.ValidAlias(alias) {
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
		// Capture both sources before creating directories, locks, backups, or metadata.
		capture, err := claudecfg.Read(platform, securityPath)
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

func outputJSON(stdout, stderr io.Writer, value any) int {
	if err := json.NewEncoder(stdout).Encode(value); err != nil {
		fmt.Fprintln(stderr, "cannot write JSON output")
		return 1
	}
	return 0
}

package main

import (
	"fmt"
	"io"

	"fasthands/internal/accounts"
	"fasthands/internal/claudecfg"
)

func refresh(m accounts.Manager, aliases []string, jsonMode bool, stdout, stderr io.Writer) int {
	metadata, err := m.Read()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	targets := make(map[string]bool, len(metadata))
	if len(aliases) == 0 {
		for id := range metadata {
			targets[id] = true
		}
	}
	for _, alias := range aliases {
		found := false
		for id, a := range metadata {
			if a.Alias == alias {
				targets[id], found = true, true
				break
			}
		}
		if !found {
			fmt.Fprintf(stderr, "invalid arguments: no account with alias %q\n", alias)
			return 2
		}
	}
	ids := make([]string, 0, len(targets))
	for id := range targets {
		ids = append(ids, id)
	}
	var loc claudecfg.Locations
	var live string
	if len(ids) != 0 {
		loc, err = claudecfg.Locate()
		if err == nil {
			live, err = claudecfg.ActiveUUID(loc)
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	results := fetchUsage(m, ids, loc, live)
	code := 0
	for _, result := range results {
		if result.Error != "" {
			code = 1
		}
	}
	if jsonMode {
		if outputJSON(stdout, stderr, struct {
			Results []accounts.FetchResult `json:"results"`
		}{results}) != 0 {
			return 1
		}
		return code
	}
	for _, result := range results {
		note := "fetched"
		if result.Skipped != "" {
			note = "skipped: " + result.Skipped
		}
		if result.Error != "" {
			note = "error: " + result.Error
		}
		fmt.Fprintf(stdout, "%s\t%s\n", result.Alias, note)
	}
	return code
}

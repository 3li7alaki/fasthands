package main

import (
	"fmt"
	"os"

	"fasthands/internal/base"
	"fasthands/internal/version"
)

const usage = "usage: fasthands [--version] [--help]"

func main() {
	switch base.Command(os.Args[1:]) {
	case "help":
		fmt.Println(usage)
	case "version":
		fmt.Println(version.Version)
	// Zero args is the placeholder branch a fresh scaffold grows its real commands into,
	// and exits 0. An unrecognized argument is a usage error: stderr, non-zero, per base.go.
	default:
		if len(os.Args) > 1 {
			fmt.Fprintln(os.Stderr, usage)
			os.Exit(1)
		}
		fmt.Println("fasthands")
	}
}

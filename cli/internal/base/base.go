// Package base holds the argument spellings every CLI in this suite answers the same way.
// It is written by `cli new`, reinstalled by `cli sync`, and compared byte for byte by
// `cli check`, so a new spelling belongs in the template, never in one repo.
package base

// Command reports which shared command these arguments name, or "" when none of them do.
// The caller owns the output, because a tool that supports --json prints its version as
// JSON and a tool that does not prints a bare string. Only the spellings are shared.
//
// Callers must answer "help" on stdout with exit 0. The installer tells users to run
// `<tool> --help`, so an explicit help request is never an error. A usage message printed
// because the arguments were wrong is a different thing and stays on stderr, non-zero.
func Command(args []string) string {
	if len(args) == 0 {
		return ""
	}
	switch args[0] {
	case "-h", "--help", "help":
		return "help"
	case "-v", "--version", "version":
		return "version"
	}
	return ""
}

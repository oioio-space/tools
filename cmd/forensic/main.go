// Command forensic is a multi-tool CLI wrapping several forensic parsers, each
// exposed as a subcommand. The first tool is `regripper`, which normalizes
// RegRipper (rip.pl) output into SIEM-ready CSV/JSON/JSONL.
//
// New tools are added by implementing command.Command and registering them in
// buildRegistry below.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/oioio-space/tools/internal/command"
	"github.com/oioio-space/tools/internal/regripper"
)

// version is overridable at build time via -ldflags "-X main.version=...".
var version = "dev"

func buildRegistry() *command.Registry {
	r := command.NewRegistry()
	r.Register(regripper.New())
	// Future forensic tools register here.
	return r
}

func main() {
	os.Exit(run(os.Args, os.Stdin, os.Stdout, os.Stderr))
}

func run(argv []string, stdin *os.File, stdout, stderr *os.File) int {
	prog := filepath.Base(argv[0])
	reg := buildRegistry()

	if len(argv) < 2 {
		reg.PrintHelp(stderr, prog)
		return 2
	}

	switch name := argv[1]; name {
	case "-h", "--help", "help":
		reg.PrintHelp(stdout, prog)
		return 0
	case "-v", "--version", "version":
		fmt.Fprintf(stdout, "%s %s\n", prog, version)
		return 0
	default:
		c, ok := reg.Get(name)
		if !ok {
			fmt.Fprintf(stderr, "unknown command %q\n\n", name)
			reg.PrintHelp(stderr, prog)
			return 2
		}
		if err := c.Run(argv[2:], stdin, stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "%s %s: %v\n", prog, name, err)
			return 1
		}
		return 0
	}
}

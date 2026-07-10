// Package command provides a tiny, dependency-free subcommand framework shared
// by every forensic tool exposed through the `forensic` CLI.
//
// Adding a new tool is intentionally cheap: implement Command in a package
// under internal/, then Register it from cmd/forensic/main.go.
package command

import (
	"fmt"
	"io"
	"sort"
)

// Command is a single subcommand of the forensic CLI (e.g. "regripper").
type Command interface {
	// Name is the token used to invoke the command: `forensic <name>`.
	Name() string
	// Synopsis is a one-line description shown in the top-level help listing.
	Synopsis() string
	// Usage returns the detailed usage/help text for the command.
	Usage() string
	// Run executes the command with the arguments following the subcommand
	// name. I/O is injected so commands stay testable and never reach for the
	// global os.Std* handles directly.
	Run(args []string, stdin io.Reader, stdout, stderr io.Writer) error
}

// Registry holds the set of available subcommands.
type Registry struct {
	commands map[string]Command
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{commands: make(map[string]Command)}
}

// Register adds a command. It panics on a duplicate name, which can only ever
// be a programming error at wire-up time.
func (r *Registry) Register(c Command) {
	name := c.Name()
	if _, exists := r.commands[name]; exists {
		panic(fmt.Sprintf("command %q already registered", name))
	}
	r.commands[name] = c
}

// Get looks up a command by name.
func (r *Registry) Get(name string) (Command, bool) {
	c, ok := r.commands[name]
	return c, ok
}

// All returns the registered commands sorted by name.
func (r *Registry) All() []Command {
	out := make([]Command, 0, len(r.commands))
	for _, c := range r.commands {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// PrintHelp writes the top-level help listing to w.
func (r *Registry) PrintHelp(w io.Writer, prog string) {
	fmt.Fprintf(w, "%s - a collection of forensic parsers\n\n", prog)
	fmt.Fprintf(w, "Usage:\n  %s <command> [flags]\n\n", prog)
	fmt.Fprintln(w, "Commands:")
	for _, c := range r.All() {
		fmt.Fprintf(w, "  %-12s %s\n", c.Name(), c.Synopsis())
	}
	fmt.Fprintf(w, "\nRun `%s <command> -h` for command-specific flags.\n", prog)
}

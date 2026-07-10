package regripper

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/oioio-space/tools/internal/command"
	"github.com/oioio-space/tools/internal/output"
)

// cmd implements command.Command for the RegRipper parser.
type cmd struct{}

// New returns the `regripper` subcommand.
func New() command.Command { return cmd{} }

func (cmd) Name() string     { return "regripper" }
func (cmd) Synopsis() string { return "Parse RegRipper (rip.pl) output into CSV/JSON/JSONL" }

func (cmd) Usage() string {
	return strings.TrimSpace(`
Usage: forensic regripper [flags]

Parses the textual output of RegRipper (rip.pl) into structured records with
timestamps normalized to RFC3339/UTC for SIEM ingestion.

Flags:
  -input   string   Input file (default "-" for stdin)
  -output  string   Output file (default "-" for stdout)
  -format  string   Output format: json, jsonl or csv (default "jsonl")
  -sort    string   Sort by field; prefix with '-' for descending.
                    Keys: timestamp, plugin, key, line. Example: -sort -timestamp
  -plugin  string   Only emit records from this plugin (case-insensitive)
  -pretty           Pretty-print JSON (only with -format json)

Examples:
  rip.pl -r NTUSER.DAT -p userassist | forensic regripper -format csv
  forensic regripper -input rip.txt -format json -sort timestamp -pretty
`)
}

func (c cmd) Run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet(c.Name(), flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintln(stderr, c.Usage()) }

	var (
		inPath  = fs.String("input", "-", "input file (\"-\" for stdin)")
		outPath = fs.String("output", "-", "output file (\"-\" for stdout)")
		format  = fs.String("format", "jsonl", "output format: json, jsonl or csv")
		sortBy  = fs.String("sort", "", "sort by field (prefix '-' for descending)")
		plugin  = fs.String("plugin", "", "only emit records from this plugin")
		pretty  = fs.Bool("pretty", false, "pretty-print JSON output")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	fmtVal, err := output.ParseFormat(*format)
	if err != nil {
		return err
	}

	in, closeIn, err := openInput(*inPath, stdin)
	if err != nil {
		return err
	}
	defer closeIn()

	records, err := Parse(in)
	if err != nil {
		return fmt.Errorf("parsing input: %w", err)
	}

	if *plugin != "" {
		records = filterByPlugin(records, *plugin)
	}

	if err := Sort(records, *sortBy); err != nil {
		return err
	}

	out, closeOut, err := openOutput(*outPath, stdout)
	if err != nil {
		return err
	}
	defer closeOut()

	if err := output.Write(out, fmtVal, records, *pretty); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}

func filterByPlugin(records []Record, plugin string) []Record {
	want := strings.ToLower(plugin)
	out := records[:0:0]
	for _, r := range records {
		if strings.ToLower(r.Plugin) == want {
			out = append(out, r)
		}
	}
	return out
}

func openInput(path string, stdin io.Reader) (io.Reader, func(), error) {
	if path == "" || path == "-" {
		return stdin, func() {}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("opening input: %w", err)
	}
	return f, func() { f.Close() }, nil
}

func openOutput(path string, stdout io.Writer) (io.Writer, func(), error) {
	if path == "" || path == "-" {
		return stdout, func() {}, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("creating output: %w", err)
	}
	return f, func() { f.Close() }, nil
}

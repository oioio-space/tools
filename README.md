# tools

A collection of small, dependency-free **forensic tools written in Go**.

Everything is exposed through a single CLI, `forensic`, with one **subcommand
per tool**. The goal is normalized, SIEM-ready output (CSV / JSON / JSONL) with
timestamps that ingestion pipelines understand out of the box (RFC3339, UTC).

## Layout

```
.
├── cmd/
│   └── forensic/          # the `forensic` CLI entry point + subcommand wiring
├── internal/
│   ├── command/           # tiny subcommand framework (Command interface + registry)
│   ├── output/            # shared CSV / JSON / JSONL writers
│   ├── timeparse/         # shared timestamp normalization → RFC3339 / UTC
│   └── regripper/         # tool: RegRipper (rip.pl) output parser
└── go.mod
```

Each tool lives in its own `internal/<tool>` package and exposes a
`command.Command`. Adding a tool is: write the package, then register it in
`cmd/forensic/main.go`. Shared concerns (timestamp parsing, output formatting)
stay in `internal/timeparse` and `internal/output` so every tool behaves the
same way.

## Build

```sh
make build          # -> ./bin/forensic, with an auto-incrementing version
```

The version is derived from git as `0.1.<commit-count>+g<short-hash>` (plus
`-dirty` for an uncommitted tree), so it rises on every commit/push with no
manual bump. It shows in the top-level help header and via `forensic version`.
`make version` prints the value without building.

A plain `go build -o forensic ./cmd/forensic` also works; it keeps the in-code
default version instead of the git-derived one.

## Usage

```
forensic <command> [flags]

Commands:
  regripper    Parse RegRipper (rip.pl) output into CSV/JSON/JSONL

forensic <command> -h   # command-specific flags
```

## Tools

### `regripper` — RegRipper (rip.pl) parser

Parses the free-form text emitted by [RegRipper](https://github.com/keydet89/RegRipper3.0)
(`rip.pl` / `rip.exe`) into structured records. Almost every plugin shares one
shape: an **anchor** line — a registry key path or a timestamp — followed by one
or more lines describing it (values, entries, a `LastWrite` time). The parser
groups each anchor together with its following lines into a **single event
record**, so one JSONL line is one whole event (timestamp + message), not one
physical text line.

**Timestamps** from every supported plugin format — Perl `ctime`
(`Wed Nov 25 20:00:00 2015 (UTC)`), ISO variants, offset-bearing RFC3339 — are
normalized to **RFC3339 in UTC** (`2015-11-25T20:00:00Z`) so Splunk, Elastic,
Sentinel, Chronicle, etc. parse them without custom rules.

```
Usage: forensic regripper [flags]

  -input   string   Input file (default "-" for stdin)
  -output  string   Output file (default "-" for stdout)
  -format  string   json | jsonl | csv (default "jsonl")
  -sort    string   Sort by field; prefix '-' for descending.
                    Keys: timestamp, plugin, key, line
  -plugin  string   Only emit records from this plugin (case-insensitive)
  -pretty           Pretty-print JSON (with -format json)
```

Records without a timestamp sort **after** timestamped ones (ascending), so the
timeline stays clean at the top.

**Examples**

```sh
# Pipe rip.pl straight in, get JSONL
rip.pl -r NTUSER.DAT -p userassist | forensic regripper

# Parse a saved report to CSV, sorted chronologically
forensic regripper -input rip.txt -format csv -sort timestamp

# Newest first, pretty JSON, only the shellbags plugin
forensic regripper -input rip.txt -format json -pretty -sort -timestamp -plugin shellbags
```

**Record fields**

Field names follow the schema [Timesketch](https://timesketch.org) expects on
import — `datetime`, `timestamp_desc` and `message` are its three required
fields — so the JSONL/CSV can be ingested directly.

| Field            | Description                                                        |
|------------------|--------------------------------------------------------------------|
| `datetime`       | full RFC3339/UTC (ISO-8601); Timesketch's event time              |
| `timestamp_desc` | what the datetime means: `LastWrite Time` or `Registry Timestamp`  |
| `date`           | UTC date part of `datetime` (`YYYY-MM-DD`), as a separate field    |
| `time`           | UTC time part of `datetime` (`HH:MM:SS`), as a separate field      |
| `type`           | `key` (key anchor), `event` (timestamp anchor) or `info`           |
| `plugin`         | RegRipper plugin the event belongs to                             |
| `key_path`       | registry key in scope                                              |
| `last_write`     | `LastWrite` time of the enclosing key (RFC3339/UTC)               |
| `line`           | 1-based line number where the event's anchor starts               |
| `message`        | the event body (following lines joined; never dropped)            |

`datetime` (combined) and `date` + `time` (split) all refer to the same instant
in UTC; use whichever your pipeline indexes. Time fields are empty when a record
has no timestamp. CSV columns follow the same order as the table above.

## Test

```sh
go test ./...
```

## Roadmap

- Additional forensic parsers as new subcommands (e.g. other DFIR tool outputs).
- More sort keys and field filters.

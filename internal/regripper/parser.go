// Package regripper parses the textual output of RegRipper (rip.pl) into
// structured, SIEM-ready records.
//
// RegRipper runs a plugin (or a profile of many plugins) against a Windows
// registry hive and prints free-form text. There is no single machine-readable
// schema across the ~hundreds of plugins, so this parser takes a robust,
// line-oriented approach: it walks the output, carrying forward the contextual
// state that RegRipper prints once and then references implicitly — the current
// plugin, the current registry key, and that key's LastWrite time — and emits
// one record per meaningful line, each stamped with the best timestamp known at
// that point. Every record keeps its raw message so nothing is lost.
package regripper

import (
	"bufio"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/oioio-space/tools/internal/timeparse"
)

// Record is a single normalized event extracted from rip.pl output.
type Record struct {
	// Timestamp is RFC3339/UTC, ready for SIEM ingestion. It is the timestamp
	// found on this line if any, otherwise the enclosing key's LastWrite time.
	Timestamp string `json:"timestamp,omitempty"`
	// Type classifies the line: plugin, key, lastwrite, event or info.
	Type string `json:"type"`
	// Plugin is the RegRipper plugin the line belongs to.
	Plugin string `json:"plugin,omitempty"`
	// KeyPath is the registry key currently in scope.
	KeyPath string `json:"key_path,omitempty"`
	// LastWrite is the RFC3339/UTC LastWrite time of the current key.
	LastWrite string `json:"last_write,omitempty"`
	// Message is the raw (trimmed) source line.
	Message string `json:"message"`
	// Line is the 1-based line number in the input.
	Line int `json:"line"`

	// ts / hasTS hold the parsed Timestamp for sorting. Unexported so they stay
	// out of JSON/CSV output.
	ts    time.Time
	hasTS bool
}

// Record type classifications.
const (
	TypePlugin    = "plugin"    // a "plugin v.YYYYMMDD" banner
	TypeKey       = "key"       // a registry key path
	TypeLastWrite = "lastwrite" // a LastWrite time line
	TypeEvent     = "event"     // a line carrying its own timestamp
	TypeInfo      = "info"      // any other content line
)

// Time returns the parsed timestamp and whether one is present. Used for
// sorting.
func (r Record) Time() (time.Time, bool) { return r.ts, r.hasTS }

// CSVHeader returns the CSV column order for Record.
func (Record) CSVHeader() []string {
	return []string{"timestamp", "type", "plugin", "key_path", "last_write", "line", "message"}
}

// CSVRow returns the CSV values for Record, aligned with CSVHeader.
func (r Record) CSVRow() []string {
	return []string{
		r.Timestamp, r.Type, r.Plugin, r.KeyPath, r.LastWrite,
		strconv.Itoa(r.Line), r.Message,
	}
}

var (
	// "Launching userassist v.20160528" or "userassist v.20160528".
	pluginRe = regexp.MustCompile(`^(?:Launching\s+)?([A-Za-z0-9_.-]+)\s+v\.?\s*(\d{6,8}|\d+\.\d+)\s*$`)
	// A run of dashes/equals RegRipper uses as a separator.
	separatorRe = regexp.MustCompile(`^[-=_]{3,}\s*$`)
	// A non-indented line that looks like a registry key path (has a backslash
	// and no whitespace in the leading path component).
	keyPathRe = regexp.MustCompile(`^[A-Za-z0-9]\S*\\\S`)
	// LastWrite lines, e.g. "LastWrite Time Wed Nov 25 20:00:00 2015 (UTC)".
	lastWriteRe = regexp.MustCompile(`(?i)last\s*write`)
)

// Parse reads rip.pl output from r and returns the extracted records. The
// source label (e.g. a file name) is attached to nothing directly but callers
// may set it; it is accepted for symmetry and future use.
func Parse(r io.Reader) ([]Record, error) {
	sc := bufio.NewScanner(r)
	// RegRipper lines are short, but some plugins dump large binary blobs; give
	// the scanner room so it never chokes on a long line.
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var (
		records    []Record
		curPlugin  string
		curKey     string
		curLW      string // current key's LastWrite, RFC3339
		curLWTime  time.Time
		curLWHasTS bool
		lineNo     int
	)

	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)

		// Drop blank lines and pure separators — they carry no data.
		if trimmed == "" || separatorRe.MatchString(trimmed) {
			continue
		}

		// Plugin banner: update scope and reset key/LastWrite context.
		if m := pluginRe.FindStringSubmatch(trimmed); m != nil {
			curPlugin = m[1]
			curKey = ""
			curLW = ""
			curLWTime = time.Time{}
			curLWHasTS = false
			records = append(records, Record{
				Type: TypePlugin, Plugin: curPlugin, Message: trimmed, Line: lineNo,
			})
			continue
		}

		rec := Record{Plugin: curPlugin, Message: trimmed, Line: lineNo}

		// LastWrite line: extract and remember for the enclosing key.
		if lastWriteRe.MatchString(trimmed) {
			if t, ok := timeparse.ExtractFirst(trimmed); ok {
				curLWTime, curLWHasTS = t, true
				curLW = timeparse.Format(t)
			}
			rec.Type = TypeLastWrite
			rec.KeyPath = curKey
			rec.LastWrite = curLW
			rec.Timestamp = curLW
			rec.ts, rec.hasTS = curLWTime, curLWHasTS
			records = append(records, rec)
			continue
		}

		// Registry key path: becomes the current scope.
		if !strings.HasPrefix(raw, " ") && !strings.HasPrefix(raw, "\t") &&
			keyPathRe.MatchString(trimmed) {
			curKey = trimmed
			rec.Type = TypeKey
			rec.KeyPath = curKey
			// A fresh key may reset LastWrite; keep the previous one only until a
			// new LastWrite line arrives, but do not carry a stale time onto the
			// key line itself.
			rec.LastWrite = curLW
			rec.Timestamp = curLW
			rec.ts, rec.hasTS = curLWTime, curLWHasTS
			records = append(records, rec)
			continue
		}

		// Any other content line. Prefer a timestamp on the line itself;
		// otherwise fall back to the enclosing key's LastWrite time.
		rec.KeyPath = curKey
		rec.LastWrite = curLW
		if t, ok := timeparse.ExtractFirst(trimmed); ok {
			rec.Type = TypeEvent
			rec.Timestamp = timeparse.Format(t)
			rec.ts, rec.hasTS = t, true
		} else {
			rec.Type = TypeInfo
			rec.Timestamp = curLW
			rec.ts, rec.hasTS = curLWTime, curLWHasTS
		}
		records = append(records, rec)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

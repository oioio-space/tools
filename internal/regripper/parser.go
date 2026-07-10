// Package regripper parses the textual output of RegRipper (rip.pl) into
// structured, SIEM-ready records.
//
// RegRipper runs a plugin (or a profile of many plugins) against a Windows
// registry hive and prints free-form text. There is no single machine-readable
// schema across its many plugins, but almost all of them share one shape: an
// "anchor" line — a registry key path, or a timestamp — followed by one or more
// lines describing that anchor (values, entries, a LastWrite time). This parser
// groups each anchor together with its following lines into a SINGLE event
// record, rather than emitting one record per physical line. Timestamps are
// normalized to RFC3339/UTC so SIEMs ingest them without custom rules.
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
	// Datetime is the full RFC3339/UTC value. It uses the field name Timesketch
	// expects for its ISO-8601 event time. For a key event it is the key's
	// LastWrite time; for a timestamp event it is the event's own time.
	Datetime string `json:"datetime,omitempty"`
	// TimestampDesc labels what the datetime represents (Timesketch's
	// timestamp_desc), e.g. "LastWrite Time".
	TimestampDesc string `json:"timestamp_desc,omitempty"`
	// Date and Time are the same instant split into separate UTC fields
	// (YYYY-MM-DD and HH:MM:SS) for tools/pipelines that index them apart.
	Date string `json:"date,omitempty"`
	Time string `json:"time,omitempty"`
	// Type classifies the event: key, event or info.
	Type string `json:"type"`
	// Plugin is the RegRipper plugin the event belongs to.
	Plugin string `json:"plugin,omitempty"`
	// KeyPath is the registry key in scope for the event.
	KeyPath string `json:"key_path,omitempty"`
	// LastWrite is the RFC3339/UTC LastWrite time of the enclosing key.
	LastWrite string `json:"last_write,omitempty"`
	// Message is the event body: the anchor's following lines joined together
	// (newline-separated). Never drops data.
	Message string `json:"message,omitempty"`
	// Line is the 1-based line number where the event's anchor starts.
	Line int `json:"line"`

	// ts / hasTS hold the parsed Timestamp for sorting. Unexported so they stay
	// out of JSON/CSV output.
	ts    time.Time
	hasTS bool
}

// Record type classifications.
const (
	TypeKey   = "key"   // anchored on a registry key path
	TypeEvent = "event" // anchored on a timestamp
	TypeInfo  = "info"  // free-standing text with no timestamp anchor
)

// timestamp_desc values (Timesketch labels for the datetime's meaning).
const (
	descLastWrite = "LastWrite Time"     // time came from a key's LastWrite
	descTimestamp = "Registry Timestamp" // time came from a value/entry line
)

// Layouts for the split Date and Time fields (both UTC).
const (
	dateLayout = "2006-01-02"
	timeLayout = "15:04:05"
)

// parsedTS returns the parsed timestamp and whether one is present. Used for
// sorting.
func (r Record) parsedTS() (time.Time, bool) { return r.ts, r.hasTS }

// CSVHeader returns the CSV column order for Record.
func (Record) CSVHeader() []string {
	return []string{"datetime", "timestamp_desc", "date", "time", "type", "plugin", "key_path", "last_write", "line", "message"}
}

// CSVRow returns the CSV values for Record, aligned with CSVHeader.
func (r Record) CSVRow() []string {
	return []string{
		r.Datetime, r.TimestampDesc, r.Date, r.Time, r.Type, r.Plugin, r.KeyPath, r.LastWrite,
		strconv.Itoa(r.Line), r.Message,
	}
}

var (
	// "Launching userassist v.20160528" or "userassist v.20160528".
	pluginRe = regexp.MustCompile(`^(?:Launching\s+)?([A-Za-z0-9_.-]+)\s+v\.?\s*(\d{6,8}|\d+\.\d+)\s*$`)
	// A run of dashes/equals RegRipper uses as a separator.
	separatorRe = regexp.MustCompile(`^[-=_*]{3,}\s*$`)
	// A non-indented line that looks like a registry key path.
	keyPathRe = regexp.MustCompile(`^[A-Za-z0-9{]\S*\\\S`)
	// A filesystem drive path (e.g. "C:\Users\..."), which is data, not a key.
	drivePathRe = regexp.MustCompile(`^[A-Za-z]:\\`)
	// LastWrite metadata lines, e.g. "LastWrite Time Wed Nov 25 20:00:00 2015
	// (UTC)" or "LastWrite: ...". Anchored at the start so prose that merely
	// mentions "LastWrite" (e.g. a plugin's own description) is not mistaken for
	// one.
	lastWriteRe = regexp.MustCompile(`(?i)^last\s*write`)
	// Timezone tokens that may trail a bare timestamp on an anchor line.
	leadingTZRe = regexp.MustCompile(`^(?:\(UTC\)|\(GMT\)|UTC|GMT|Z)(?:\s+|$)`)
)

// pending accumulates the lines of the event currently being built.
type pending struct {
	active bool
	isKey  bool // anchored on a registry key path
	ts     time.Time
	hasTS  bool
	tsStr  string
	tsDesc string
	plugin string
	key    string
	last   string
	msg    []string
	line   int
}

// recordType derives the record Type from the pending event's final state, so a
// line that only picks up a timestamp from a later continuation still lands as
// an "event" rather than "info".
func (p pending) recordType() string {
	switch {
	case p.isKey:
		return TypeKey
	case p.hasTS:
		return TypeEvent
	default:
		return TypeInfo
	}
}

// Parse reads rip.pl output from r and returns the extracted event records.
func Parse(r io.Reader) ([]Record, error) {
	sc := bufio.NewScanner(r)
	// Some plugins dump large binary blobs; give the scanner room.
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var (
		records []Record
		plugin  string
		keyPath string
		lastStr string
		lastT   time.Time
		lastHas bool
		p       pending
		lineNo  int
	)

	flush := func() {
		if !p.active {
			return
		}
		rec := Record{
			Datetime:      p.tsStr,
			TimestampDesc: p.tsDesc,
			Type:          p.recordType(),
			Plugin:        p.plugin,
			KeyPath:       p.key,
			LastWrite:     p.last,
			Message:       strings.Join(p.msg, "\n"),
			Line:          p.line,
			ts:            p.ts,
			hasTS:         p.hasTS,
		}
		if p.hasTS {
			rec.Date = p.ts.Format(dateLayout)
			rec.Time = p.ts.Format(timeLayout)
		}
		records = append(records, rec)
		p = pending{}
	}

	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)

		// Blank lines and separators close the current event.
		if trimmed == "" || separatorRe.MatchString(trimmed) {
			flush()
			continue
		}

		// Plugin banner: new scope, no record of its own.
		if m := pluginRe.FindStringSubmatch(trimmed); m != nil {
			flush()
			plugin, keyPath, lastStr, lastT, lastHas = m[1], "", "", time.Time{}, false
			continue
		}

		// LastWrite line: metadata for the current key. It sets context and, if
		// the pending event still lacks a time, supplies one — but is not itself
		// a record and is kept out of the message body.
		if lastWriteRe.MatchString(trimmed) {
			if t, ok := timeparse.ExtractFirst(trimmed); ok {
				lastStr, lastT, lastHas = timeparse.Format(t), t, true
				if p.active {
					p.last = lastStr
					if !p.hasTS {
						p.ts, p.hasTS, p.tsStr, p.tsDesc = t, true, lastStr, descLastWrite
					}
				}
				continue
			}
			// "LastWrite" with no parseable time is prose, not metadata: fall
			// through and treat it as normal content.
		}

		indented := strings.HasPrefix(raw, " ") || strings.HasPrefix(raw, "\t")

		// Registry key path anchor (non-indented, not a drive path).
		if !indented && keyPathRe.MatchString(trimmed) && !drivePathRe.MatchString(trimmed) {
			flush()
			keyPath = trimmed
			// A fresh key brings its own LastWrite next; drop the previous one.
			lastStr, lastT, lastHas = "", time.Time{}, false
			p = pending{active: true, isKey: true, plugin: plugin, key: keyPath, line: lineNo}
			continue
		}

		// Timestamp handling.
		t, start, end, ok := timeparse.ExtractFirstLoc(trimmed)
		anchor := ok && start == 0 // a leading timestamp opens a new event

		switch {
		case anchor:
			flush()
			p = pending{
				active: true, plugin: plugin, key: keyPath, last: lastStr,
				ts: t, hasTS: true, tsStr: timeparse.Format(t), tsDesc: descTimestamp, line: lineNo,
			}
			if rest := stripLeadingTZ(strings.TrimSpace(trimmed[end:])); rest != "" {
				p.msg = append(p.msg, rest)
			}

		case p.active:
			// Continuation line of the current event.
			p.msg = append(p.msg, trimmed)
			if ok && !p.hasTS {
				p.ts, p.hasTS, p.tsStr, p.tsDesc = t, true, timeparse.Format(t), descTimestamp
			}

		default:
			// Free-standing line with no open event.
			p = pending{active: true, plugin: plugin, key: keyPath, last: lastStr, line: lineNo, msg: []string{trimmed}}
			if ok {
				p.ts, p.hasTS, p.tsStr, p.tsDesc = t, true, timeparse.Format(t), descTimestamp
			} else if lastHas {
				p.ts, p.hasTS, p.tsStr, p.tsDesc = lastT, true, lastStr, descLastWrite
			}
		}
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func stripLeadingTZ(s string) string {
	return strings.TrimSpace(leadingTZRe.ReplaceAllString(s, ""))
}

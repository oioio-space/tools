// Package timeparse normalizes the many timestamp formats emitted by forensic
// tools into a single SIEM-friendly representation: RFC3339 in UTC (e.g.
// 2015-11-25T20:00:00Z). Splunk, Elastic/ELK, Sentinel, Chronicle and friends
// all ingest RFC3339/ISO-8601 out of the box, so that is the canonical output.
package timeparse

import (
	"regexp"
	"strings"
	"time"
)

// Canonical is the output layout: RFC3339 in UTC. This is what we hand to SIEMs.
const Canonical = time.RFC3339

var (
	whitespaceRe = regexp.MustCompile(`\s+`)

	// Perl's `gmtime`/`ctime` scalar form used by many RegRipper plugins, e.g.
	// "Wed Nov 25 20:00:00 2015" or "Wed Nov  5 09:08:07 2020" (double space for
	// single-digit days).
	ctimeRe = regexp.MustCompile(`(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+` +
		`(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+` +
		`\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}`)

	// ISO-8601 / RFC3339-ish, with optional fractional seconds and offset.
	isoRe = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?`)
)

// Timezone suffixes that carry no numeric offset and only add noise. Every
// timestamp we handle without an explicit offset is treated as UTC, which is
// how these tools intend them ("(UTC)" markers are decoration, not data).
var tzSuffixes = []string{" (UTC)", " (GMT)", " UTC", " GMT", " Z"}

// Layouts are tried in order against a cleaned string. Inputs without an
// explicit zone are parsed as UTC by time.Parse.
var layouts = []string{
	"Mon Jan 2 15:04:05 2006", // Perl ctime (whitespace collapsed beforehand)
	time.RFC3339,              // 2006-01-02T15:04:05Z07:00
	time.RFC3339Nano,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05.000",
	"2006-01-02 15:04:05",
	"2006/01/02 15:04:05",
	"01/02/2006 15:04:05",
	"2006-01-02",
}

// Clean strips decorative timezone markers and collapses internal whitespace so
// a single ctime layout matches both single- and double-space day fields.
func Clean(s string) string {
	s = strings.TrimSpace(s)
	changed := true
	for changed {
		changed = false
		for _, suf := range tzSuffixes {
			if strings.HasSuffix(s, suf) {
				s = strings.TrimSpace(strings.TrimSuffix(s, suf))
				changed = true
			}
		}
	}
	return whitespaceRe.ReplaceAllString(s, " ")
}

// Parse attempts to interpret s as a timestamp in one of the known layouts.
// The returned time is always in UTC.
func Parse(s string) (time.Time, bool) {
	s = Clean(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// ExtractFirst finds the first timestamp embedded anywhere in line and returns
// it. This is what lets us pull a LastWrite time out of a decorated line such
// as "LastWrite Time Wed Nov 25 20:00:00 2015 (UTC)".
func ExtractFirst(line string) (time.Time, bool) {
	if m := ctimeRe.FindString(line); m != "" {
		if t, ok := Parse(m); ok {
			return t, true
		}
	}
	if m := isoRe.FindString(line); m != "" {
		if t, ok := Parse(m); ok {
			return t, true
		}
	}
	return time.Time{}, false
}

// Format renders t in the canonical SIEM layout (RFC3339, UTC).
func Format(t time.Time) string {
	return t.UTC().Format(Canonical)
}

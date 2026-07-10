package regripper

import (
	"strings"
	"testing"
)

// A representative slice of rip.pl output covering a plugin banner, a key path,
// a LastWrite line, indented value lines and an inline timestamp.
const sample = `Launching userassist v.20160528
userassist v.20160528
(NTUSER.DAT) Displays contents of user's UserAssist key

UserAssist
Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
LastWrite Time Wed Nov 25 20:00:00 2015 (UTC)

  Value one  (2)
  Value two  (5)

Launching shellbags v.20170302
shellbags v.20170302
Shell\BagMRU
LastWrite: Thu Aug 20 12:34:56 2020 Z
  2020-08-20 12:00:00  C:\Users\bob\Desktop
`

func parse(t *testing.T, s string) []Record {
	t.Helper()
	recs, err := Parse(strings.NewReader(s))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return recs
}

func TestParsePluginAndKeyContext(t *testing.T) {
	recs := parse(t, sample)

	var uaKey, lastWrite, valueLine *Record
	for i := range recs {
		r := &recs[i]
		switch {
		case r.Type == TypeKey && strings.Contains(r.KeyPath, "UserAssist"):
			uaKey = r
		case r.Type == TypeLastWrite && r.Plugin == "userassist":
			lastWrite = r
		case r.Message == "Value one  (2)":
			valueLine = r
		}
	}

	if uaKey == nil {
		t.Fatal("did not classify the UserAssist key path")
	}
	if uaKey.Plugin != "userassist" {
		t.Errorf("key plugin = %q, want userassist", uaKey.Plugin)
	}
	if lastWrite == nil || lastWrite.Timestamp != "2015-11-25T20:00:00Z" {
		t.Fatalf("LastWrite record wrong: %+v", lastWrite)
	}
	// Value lines with no timestamp of their own inherit the key's LastWrite.
	if valueLine == nil {
		t.Fatal("value line not found")
	}
	if valueLine.Timestamp != "2015-11-25T20:00:00Z" {
		t.Errorf("value inherited timestamp = %q, want key LastWrite", valueLine.Timestamp)
	}
	if valueLine.Plugin != "userassist" {
		t.Errorf("value plugin = %q, want userassist", valueLine.Plugin)
	}
}

func TestParseInlineTimestampWins(t *testing.T) {
	recs := parse(t, sample)
	var event *Record
	for i := range recs {
		if strings.Contains(recs[i].Message, "Desktop") {
			event = &recs[i]
		}
	}
	if event == nil {
		t.Fatal("desktop event line not found")
	}
	if event.Type != TypeEvent {
		t.Errorf("type = %q, want event", event.Type)
	}
	// The line's own timestamp beats the enclosing LastWrite.
	if event.Timestamp != "2020-08-20T12:00:00Z" {
		t.Errorf("timestamp = %q, want inline 2020-08-20T12:00:00Z", event.Timestamp)
	}
	if event.Plugin != "shellbags" {
		t.Errorf("plugin = %q, want shellbags", event.Plugin)
	}
}

func TestPluginBannerResetsContext(t *testing.T) {
	recs := parse(t, sample)
	// After the shellbags banner, no record should still carry the userassist
	// key path.
	seenShellbags := false
	for _, r := range recs {
		if r.Type == TypePlugin && r.Plugin == "shellbags" {
			seenShellbags = true
		}
		if seenShellbags && strings.Contains(r.KeyPath, "UserAssist") {
			t.Errorf("stale UserAssist key leaked into shellbags: %+v", r)
		}
	}
}

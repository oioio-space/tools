package regripper

import (
	"strings"
	"testing"
)

func parse(t *testing.T, s string) []Record {
	t.Helper()
	recs, err := Parse(strings.NewReader(s))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return recs
}

// find returns the first record whose message contains sub.
func find(recs []Record, sub string) *Record {
	for i := range recs {
		if strings.Contains(recs[i].Message, sub) {
			return &recs[i]
		}
	}
	return nil
}

// A key anchor followed by a LastWrite line and several value lines must
// collapse into a single record carrying the LastWrite timestamp.
func TestKeyGroupsValuesIntoOneRecord(t *testing.T) {
	const in = `Launching recentdocs v.20200427
recentdocs v.20200427

Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
LastWrite Time Thu Aug 20 12:34:56 2020 (UTC)
  1 = report.docx
  2 = budget.xlsx
`
	recs := parse(t, in)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d: %+v", len(recs), recs)
	}
	r := recs[0]
	if r.Type != TypeKey {
		t.Errorf("type = %q, want key", r.Type)
	}
	if r.Plugin != "recentdocs" {
		t.Errorf("plugin = %q, want recentdocs", r.Plugin)
	}
	if r.Timestamp != "2020-08-20T12:34:56Z" {
		t.Errorf("timestamp = %q, want key LastWrite", r.Timestamp)
	}
	if r.Message != "1 = report.docx\n2 = budget.xlsx" {
		t.Errorf("message = %q, want the two values joined", r.Message)
	}
}

// A bare timestamp anchor followed by one or more message lines must collapse
// into a single record — this is the reported bug.
func TestTimestampGroupsFollowingLines(t *testing.T) {
	const in = `Launching userassist v.20160528
userassist v.20160528

Wed Nov 25 20:00:00 2015 Z
  C:\Windows\notepad.exe (3)
  additional detail
`
	recs := parse(t, in)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d: %+v", len(recs), recs)
	}
	r := recs[0]
	if r.Type != TypeEvent {
		t.Errorf("type = %q, want event", r.Type)
	}
	if r.Timestamp != "2015-11-25T20:00:00Z" {
		t.Errorf("timestamp = %q", r.Timestamp)
	}
	want := "C:\\Windows\\notepad.exe (3)\nadditional detail"
	if r.Message != want {
		t.Errorf("message = %q, want %q", r.Message, want)
	}
}

// A timestamp with trailing text on the same line keeps the text as the message
// and does not duplicate the timestamp.
func TestInlineTimestampWithTrailingText(t *testing.T) {
	const in = `Launching shellbags v.20170302
shellbags v.20170302
Thu Aug 20 12:34:56 2020 (UTC)  C:\Users\bob\Desktop
`
	recs := parse(t, in)
	r := find(recs, "Desktop")
	if r == nil {
		t.Fatal("desktop record not found")
	}
	if r.Timestamp != "2020-08-20T12:34:56Z" {
		t.Errorf("timestamp = %q", r.Timestamp)
	}
	if r.Message != `C:\Users\bob\Desktop` {
		t.Errorf("message = %q, want the path only", r.Message)
	}
}

// Each bare-timestamp anchor starts a new event; two adjacent timestamped
// entries must not merge.
func TestAdjacentTimestampsAreSeparateRecords(t *testing.T) {
	const in = `Launching p v.20200101
p v.20200101
2019-01-01 00:00:00  first
2020-02-02 00:00:00  second
`
	recs := parse(t, in)
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d: %+v", len(recs), recs)
	}
	if recs[0].Message != "first" || recs[1].Message != "second" {
		t.Errorf("messages = %q / %q", recs[0].Message, recs[1].Message)
	}
}

func TestPluginBannerResetsContext(t *testing.T) {
	const in = `Launching userassist v.20160528
userassist v.20160528
Software\Microsoft\...\UserAssist
LastWrite Time Wed Nov 25 20:00:00 2015 (UTC)

Launching shellbags v.20170302
shellbags v.20170302
Shell\BagMRU
`
	recs := parse(t, in)
	for _, r := range recs {
		if r.Plugin == "shellbags" && strings.Contains(r.KeyPath, "UserAssist") {
			t.Errorf("stale UserAssist key leaked into shellbags: %+v", r)
		}
	}
	// No banner/lastwrite noise records: the two plugins yield two key records.
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d: %+v", len(recs), recs)
	}
}

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

// Real 'services' plugin output: a timestamp anchor followed by indented
// key=value fields. Also guards against the plugin's own description line
// ("...by LastWrite times") being mistaken for a LastWrite metadata line.
func TestRealServicesOutput(t *testing.T) {
	const in = `ControlSet001\Services
Lists services/drivers in Services key by LastWrite times

Fri Jan 18 00:38:13 2008Z
  Name      = MSKSSRV
  Display   = Microsoft Streaming Service Proxy
  ImagePath = system32\drivers\MSKSSRV.sys
  Type      = Kernel driver
`
	recs := parse(t, in)
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d: %+v", len(recs), recs)
	}
	// The description must survive (not swallowed as a LastWrite line).
	if recs[0].Type != TypeKey || !strings.Contains(recs[0].Message, "Lists services/drivers") {
		t.Errorf("key record lost its description: %+v", recs[0])
	}
	// The service and all its fields collapse into one timestamped event.
	svc := recs[1]
	if svc.Timestamp != "2008-01-18T00:38:13Z" {
		t.Errorf("service timestamp = %q", svc.Timestamp)
	}
	for _, want := range []string{"Name      = MSKSSRV", "ImagePath = system32\\drivers\\MSKSSRV.sys", "Type      = Kernel driver"} {
		if !strings.Contains(svc.Message, want) {
			t.Errorf("service message missing %q; got %q", want, svc.Message)
		}
	}
}

// Real 'samparse' output: a block of column-0 "Field : value" lines with a
// timestamp buried mid-line must collapse into one record per account and pick
// up the Account Created time.
func TestRealSamparseOutput(t *testing.T) {
	const in = `Username        : Administrator [500]
SID             : S-1-5-21-2734969515-1644526556-1039763013-500
Account Created : Tue Mar 27 12:13:26 2018 Z
Login Count     : 0

Username        : Guest [501]
Account Created : Wed Mar 28 09:00:00 2018 Z
`
	recs := parse(t, in)
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d: %+v", len(recs), recs)
	}
	if recs[0].Timestamp != "2018-03-27T12:13:26Z" {
		t.Errorf("admin timestamp = %q", recs[0].Timestamp)
	}
	if !strings.Contains(recs[0].Message, "Username        : Administrator [500]") {
		t.Errorf("admin record missing username line: %q", recs[0].Message)
	}
	if recs[1].Timestamp != "2018-03-28T09:00:00Z" {
		t.Errorf("guest timestamp = %q", recs[1].Timestamp)
	}
}

// The timestamp is also exposed split into separate UTC date and time fields.
func TestSplitDateAndTimeFields(t *testing.T) {
	const in = `Software\Key
LastWrite Time Wed Nov 25 20:07:09 2015 (UTC)
  value
`
	recs := parse(t, in)
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	r := recs[0]
	if r.Timestamp != "2015-11-25T20:07:09Z" {
		t.Errorf("timestamp = %q", r.Timestamp)
	}
	if r.Date != "2015-11-25" {
		t.Errorf("date = %q, want 2015-11-25", r.Date)
	}
	if r.Time != "20:07:09" {
		t.Errorf("time = %q, want 20:07:09", r.Time)
	}
}

// Records without a timestamp leave the date and time fields empty.
func TestSplitFieldsEmptyWithoutTimestamp(t *testing.T) {
	recs := parse(t, "just a line with no time\n")
	if len(recs) != 1 {
		t.Fatalf("want 1 record, got %d", len(recs))
	}
	if recs[0].Date != "" || recs[0].Time != "" {
		t.Errorf("expected empty date/time, got %q / %q", recs[0].Date, recs[0].Time)
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

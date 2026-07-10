package regripper

import (
	"strings"
	"testing"
	"time"
)

func mkRec(line int, ts string) Record {
	r := Record{Line: line}
	if ts != "" {
		t, _ := time.Parse(time.RFC3339, ts)
		r.ts, r.hasTS, r.Datetime = t, true, ts
	}
	return r
}

func TestSortTimestampAscending(t *testing.T) {
	recs := []Record{
		mkRec(1, "2020-01-02T00:00:00Z"),
		mkRec(2, ""), // no timestamp -> should sink to the end
		mkRec(3, "2019-01-01T00:00:00Z"),
	}
	if err := Sort(recs, "timestamp"); err != nil {
		t.Fatal(err)
	}
	if recs[0].Line != 3 || recs[1].Line != 1 {
		t.Errorf("ascending order wrong: %d, %d", recs[0].Line, recs[1].Line)
	}
	if recs[2].Line != 2 {
		t.Errorf("record without timestamp should sort last, got line %d", recs[2].Line)
	}
}

func TestSortDescending(t *testing.T) {
	recs := []Record{
		mkRec(1, "2019-01-01T00:00:00Z"),
		mkRec(2, "2021-01-01T00:00:00Z"),
	}
	if err := Sort(recs, "-timestamp"); err != nil {
		t.Fatal(err)
	}
	if recs[0].Line != 2 {
		t.Errorf("descending order wrong, first line = %d", recs[0].Line)
	}
}

func TestSortUnknownKey(t *testing.T) {
	err := Sort([]Record{}, "bogus")
	if err == nil || !strings.Contains(err.Error(), "unknown sort key") {
		t.Errorf("want unknown sort key error, got %v", err)
	}
}

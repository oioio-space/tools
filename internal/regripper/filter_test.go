package regripper

import "testing"

func TestEventsDropsUntimedLines(t *testing.T) {
	const in = `Launching userassist v.20200330
userassist v.20200330
(NTUSER.DAT) Displays contents of user's UserAssist key

Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
LastWrite Time 2013-06-03 15:20:46Z
  C:\Windows\notepad.exe (5)
`
	all := parse(t, in)
	// The description line parses to an untimed info record.
	if got := len(all); got < 2 {
		t.Fatalf("expected the description plus the key record, got %d: %+v", got, all)
	}

	ev := Events(all)
	if len(ev) != 1 {
		t.Fatalf("Events kept %d records, want 1: %+v", len(ev), ev)
	}
	if ev[0].Type != TypeKey || ev[0].Datetime != "2013-06-03T15:20:46Z" {
		t.Errorf("kept the wrong record: %+v", ev[0])
	}
	// Every kept record must have a datetime.
	for _, r := range ev {
		if r.Datetime == "" {
			t.Errorf("Events kept an untimed record: %+v", r)
		}
	}
}

func TestEventsEmptyInput(t *testing.T) {
	if got := Events(nil); len(got) != 0 {
		t.Errorf("Events(nil) = %v, want empty", got)
	}
}

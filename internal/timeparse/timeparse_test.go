package timeparse

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want string // RFC3339 UTC, or "" if it should not parse
	}{
		{"Wed Nov 25 20:00:00 2015 (UTC)", "2015-11-25T20:00:00Z"},
		{"Wed Nov  5 09:08:07 2020 Z", "2020-11-05T09:08:07Z"}, // double space, single-digit day
		{"Thu Aug 20 12:34:56 2020", "2020-08-20T12:34:56Z"},
		{"2015-11-25 20:00:00", "2015-11-25T20:00:00Z"},
		{"2015-11-25T20:00:00Z", "2015-11-25T20:00:00Z"},
		{"2020-08-20T12:34:56+02:00", "2020-08-20T10:34:56Z"}, // offset normalized to UTC
		{"2015-11-25", "2015-11-25T00:00:00Z"},
		{"not a timestamp", ""},
		{"", ""},
	}
	for _, c := range cases {
		got, ok := Parse(c.in)
		if c.want == "" {
			if ok {
				t.Errorf("Parse(%q) = %v, want no parse", c.in, got)
			}
			continue
		}
		if !ok {
			t.Errorf("Parse(%q) failed, want %s", c.in, c.want)
			continue
		}
		if s := Format(got); s != c.want {
			t.Errorf("Parse(%q) = %s, want %s", c.in, s, c.want)
		}
	}
}

func TestExtractFirst(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"LastWrite Time Wed Nov 25 20:00:00 2015 (UTC)", "2015-11-25T20:00:00Z"},
		{"  ran at 2020-08-20 12:34:56 UTC then stopped", "2020-08-20T12:34:56Z"},
		{"no timestamp here", ""},
	}
	for _, c := range cases {
		got, ok := ExtractFirst(c.in)
		if c.want == "" {
			if ok {
				t.Errorf("ExtractFirst(%q) = %v, want none", c.in, got)
			}
			continue
		}
		if !ok || Format(got) != c.want {
			t.Errorf("ExtractFirst(%q) = %v/%v, want %s", c.in, got, ok, c.want)
		}
	}
}

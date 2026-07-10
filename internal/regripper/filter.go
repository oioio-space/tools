package regripper

// Events returns only the records that carry a timestamp.
//
// RegRipper output is interleaved with header, banner and description text that
// are not timeline events and have no timestamp to parse. Keeping only records
// with a datetime makes output effectively begin at the first timestamp — and
// still retains key events, since a key record takes its time from the
// following LastWrite line.
func Events(records []Record) []Record {
	out := records[:0:0]
	for _, r := range records {
		if r.hasTS {
			out = append(out, r)
		}
	}
	return out
}

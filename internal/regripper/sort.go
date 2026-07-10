package regripper

import (
	"fmt"
	"sort"
	"strings"
)

// SortKeys lists the record fields records can be sorted by.
var SortKeys = []string{"timestamp", "plugin", "key", "line"}

// Sort orders records in place by the given spec. The spec is a field name
// optionally prefixed with '-' for descending order (e.g. "timestamp" or
// "-timestamp"). An empty spec leaves the records untouched.
//
// The sort is stable, so records that compare equal keep their original input
// order — which for rip.pl output is the order the tool emitted them.
func Sort(records []Record, spec string) error {
	if strings.TrimSpace(spec) == "" {
		return nil
	}
	desc := false
	field := spec
	if strings.HasPrefix(field, "-") {
		desc = true
		field = field[1:]
	} else if strings.HasPrefix(field, "+") {
		field = field[1:]
	}
	field = strings.ToLower(strings.TrimSpace(field))

	less, err := lessFunc(records, field)
	if err != nil {
		return err
	}
	if desc {
		orig := less
		less = func(i, j int) bool { return orig(j, i) }
	}
	sort.SliceStable(records, less)
	return nil
}

func lessFunc(records []Record, field string) (func(i, j int) bool, error) {
	switch field {
	case "timestamp", "time", "ts":
		return func(i, j int) bool {
			ti, oki := records[i].parsedTS()
			tj, okj := records[j].parsedTS()
			// Records without a timestamp sort after those with one, so the
			// timeline stays clean at the top for ascending order.
			if oki != okj {
				return oki
			}
			if !oki {
				return false
			}
			return ti.Before(tj)
		}, nil
	case "plugin":
		return func(i, j int) bool { return records[i].Plugin < records[j].Plugin }, nil
	case "key", "keypath", "key_path":
		return func(i, j int) bool { return records[i].KeyPath < records[j].KeyPath }, nil
	case "line":
		return func(i, j int) bool { return records[i].Line < records[j].Line }, nil
	default:
		return nil, fmt.Errorf("unknown sort key %q (want one of: %s)",
			field, strings.Join(SortKeys, ", "))
	}
}

// Package output provides the shared CSV / JSON / JSONL writers used by every
// forensic tool so that output formatting stays consistent across the CLI.
package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
)

// Format is a supported serialization format.
type Format string

const (
	FormatJSON  Format = "json"  // a single pretty-or-compact JSON array
	FormatJSONL Format = "jsonl" // newline-delimited JSON, one record per line
	FormatCSV   Format = "csv"   // RFC 4180 CSV with a header row
)

// ParseFormat validates and normalizes a user-supplied format string.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case FormatJSON, FormatJSONL, FormatCSV:
		return Format(s), nil
	default:
		return "", fmt.Errorf("unknown format %q (want json, jsonl or csv)", s)
	}
}

// CSVMarshaler is implemented by record types that can be flattened to CSV.
// The header is a package/type-level concern, so it is exposed separately.
type CSVMarshaler interface {
	// CSVRow returns the field values for one record, aligned with CSVHeader.
	CSVRow() []string
}

// CSVHeaderer supplies the CSV column names for a record type.
type CSVHeaderer interface {
	CSVHeader() []string
}

// Write serializes items to w in the requested format.
//
// For CSV, T must implement CSVMarshaler and CSVHeaderer.
func Write[T any](w io.Writer, format Format, items []T, pretty bool) error {
	switch format {
	case FormatJSON:
		return writeJSON(w, items, pretty)
	case FormatJSONL:
		return writeJSONL(w, items)
	case FormatCSV:
		return writeCSV(w, items)
	default:
		return fmt.Errorf("unknown format %q", format)
	}
}

func writeJSON[T any](w io.Writer, items []T, pretty bool) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if pretty {
		enc.SetIndent("", "  ")
	}
	// Guarantee a JSON array even when there are zero records.
	if items == nil {
		items = []T{}
	}
	return enc.Encode(items)
}

func writeJSONL[T any](w io.Writer, items []T) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, it := range items {
		if err := enc.Encode(it); err != nil {
			return err
		}
	}
	return nil
}

func writeCSV[T any](w io.Writer, items []T) error {
	cw := csv.NewWriter(w)
	wroteHeader := false
	for _, it := range items {
		row, ok := any(it).(CSVMarshaler)
		if !ok {
			return fmt.Errorf("record type %T does not support CSV output", it)
		}
		if !wroteHeader {
			if h, ok := any(it).(CSVHeaderer); ok {
				if err := cw.Write(h.CSVHeader()); err != nil {
					return err
				}
			}
			wroteHeader = true
		}
		if err := cw.Write(row.CSVRow()); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

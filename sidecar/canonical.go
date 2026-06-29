package sidecar

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// canonicalJSON serializes v to compact JSON with sorted keys and HTML
// escaping disabled, byte-identical to Python's
// `json.dumps(v, sort_keys=True, separators=(',',':'))` for payloads that
// contain only strings, ints, bools, arrays, and nested maps (no floats).
//
// This is the exact canonicalization the MOSS server signs revocation feeds
// with, so the sidecar must reproduce it byte-for-byte to verify signatures
// offline.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("sidecar: canonical encode: %w", err)
	}
	// json.Encoder.Encode appends a trailing newline; remove it to match
	// Python's separators output (no trailing newline).
	out := bytes.TrimRight(buf.Bytes(), "\n")
	return out, nil
}

// sortedMapKeys returns the keys of m sorted lexicographically.
func sortedMapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

package native

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// decodeControlJSON rejects ambiguous objects before Go's case-insensitive
// struct decoder can merge fields or replace earlier security decisions. Unknown
// fields remain compatible, but are subject to the same structural bounds.
func decodeControlJSON(data []byte, target any) error {
	invalid := errors.New("invalid or ambiguous SSM control JSON")
	if len(data) == 0 || len(data) > 65536 || !utf8.Valid(data) {
		return invalid
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	first, err := d.Token()
	if err != nil || first != json.Delim('{') || !controlJSONValue(d, first, 1) {
		return invalid
	}
	if _, err := d.Token(); err != io.EOF {
		return invalid
	}
	if json.Unmarshal(data, target) != nil {
		return invalid
	}
	return nil
}

// Container recursion is bounded before descending. Keys are bounded per
// object, so duplicate checking cannot grow quadratically without a fixed cap.
func controlJSONValue(d *json.Decoder, token json.Token, depth int) bool {
	delim, container := token.(json.Delim)
	if !container {
		return true
	}
	if depth > 16 || (delim != '{' && delim != '[') {
		return false
	}
	keys := make([]string, 0, 8)
	for d.More() {
		if delim == '{' {
			token, err := d.Token()
			key, ok := token.(string)
			if err != nil || !ok || len(key) > 256 || len(keys) >= 64 {
				return false
			}
			for _, previous := range keys {
				if strings.EqualFold(previous, key) {
					return false
				}
			}
			keys = append(keys, key)
		}
		value, err := d.Token()
		if err != nil || !controlJSONValue(d, value, depth+1) {
			return false
		}
	}
	closing, err := d.Token()
	return err == nil && ((delim == '{' && closing == json.Delim('}')) || (delim == '[' && closing == json.Delim(']')))
}

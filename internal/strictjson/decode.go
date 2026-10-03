// Package strictjson decodes untrusted JSON without accepting ambiguous input.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode"
	"unicode/utf8"
)

// Decode decodes exactly one JSON value, rejecting duplicate and unknown fields.
// Keys are duplicates when they differ only by case, because encoding/json
// matches struct fields case-insensitively and lets the last value win.
func Decode(data []byte, target any) error {
	if target == nil {
		return errors.New("JSON target is nil")
	}

	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		return err
	}

	return ensureEOF(decoder)
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	if err := scanValue(decoder); err != nil {
		return err
	}

	return ensureEOF(decoder)
}

func scanValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}

	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})

		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}

			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			folded := foldKey(key)
			if _, exists := seen[folded]; exists {
				return fmt.Errorf("duplicate JSON field %q", key)
			}

			seen[folded] = struct{}{}

			if err := scanValue(decoder); err != nil {
				return err
			}
		}

		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanValue(decoder); err != nil {
				return err
			}
		}

		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}

	return nil
}

// foldKey returns the same canonical form for keys that bytes.EqualFold
// considers equal, matching how encoding/json resolves struct field names.
func foldKey(key string) string {
	folded := make([]byte, 0, len(key))

	for _, r := range key {
		if r < utf8.RuneSelf {
			folded = append(folded, byte(unicode.ToUpper(r)))
			continue
		}

		folded = utf8.AppendRune(folded, foldRune(r))
	}

	return string(folded)
}

// foldRune returns the smallest rune of r's simple case-folding orbit.
func foldRune(r rune) rune {
	for {
		next := unicode.SimpleFold(r)
		if next <= r {
			return next
		}

		r = next
	}
}

func ensureEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}

		return err
	}

	return nil
}

package coraza

import (
	"encoding/json"
	"fmt"
)

// Keep the recursive processor bounded even when the configured body limit is large.
const maxJSONDepth = 128

func validateJSONBody(data []byte) error {
	if !json.Valid(data) {
		return fmt.Errorf("invalid JSON request body")
	}
	depth := 0
	quoted, escaped := false, false
	for _, b := range data {
		if quoted {
			if escaped {
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				quoted = false
			}
			continue
		}
		switch b {
		case '"':
			quoted = true
		case '{', '[':
			depth++
			if depth > maxJSONDepth {
				return fmt.Errorf("JSON request body exceeds depth limit %d", maxJSONDepth)
			}
		case '}', ']':
			depth--
		}
	}
	return nil
}

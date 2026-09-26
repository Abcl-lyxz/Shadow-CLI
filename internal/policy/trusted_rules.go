package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const maxTrustedRulesBytes = 64 << 10
const maxTrustedActions = 64

// TrustedRules is an operator-authored, versioned declaration. Parsing it
// does not grant any model or tool network access; StartRun must snapshot the
// validated rules, and each dispatcher must enforce that snapshot at runtime.
type TrustedRules struct {
	Version int          `json:"version"`
	Origin  string       `json:"origin"`
	Actions []ActionRule `json:"actions"`
}

// ParseTrustedRules accepts only a bounded, strict document for the runtime's
// already selected exact origin. The caller must obtain it from a trusted
// operator, never from model output or target content.
func ParseTrustedRules(reader io.Reader, expectedOrigin string) (TrustedRules, error) {
	var document TrustedRules
	data, err := io.ReadAll(io.LimitReader(reader, maxTrustedRulesBytes+1))
	if err != nil || len(data) > maxTrustedRulesBytes {
		return document, errors.New("trusted rules file exceeds the size limit")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return document, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return TrustedRules{}, errors.New("invalid trusted rules document")
	}
	if document.Version != 1 || len(document.Actions) > maxTrustedActions {
		return TrustedRules{}, errors.New("unsupported trusted rules version or action count")
	}
	scope, err := FromTarget(expectedOrigin)
	if err != nil || scope.Origin != expectedOrigin || document.Origin != expectedOrigin {
		return TrustedRules{}, errors.New("trusted rules origin does not match the selected exact scope")
	}
	if _, err := NewActionPolicy(scope, document.Actions); err != nil {
		return TrustedRules{}, err
	}
	// A test write needs an exact read of the same named resource for post-
	// action evidence and cleanup verification. DELETE is still not granted.
	for _, action := range document.Actions {
		if action.Effect != EffectTestWrite {
			continue
		}
		foundRead := false
		for _, candidate := range document.Actions {
			if candidate.Method == http.MethodGet && candidate.URL == action.CleanupURL && candidate.Effect == EffectRead {
				foundRead = true
				break
			}
		}
		if !foundRead {
			return TrustedRules{}, errors.New("test write needs an exact read rule for its cleanup resource")
		}
	}
	return document, nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return errors.New("invalid trusted rules JSON")
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return errors.New("invalid trusted rules JSON")
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid trusted rules JSON")
				}
				folded := strings.ToLower(key)
				if _, exists := seen[folded]; exists {
					return errors.New("duplicate key in trusted rules JSON")
				}
				seen[folded] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid trusted rules JSON")
		}
		if _, err := decoder.Token(); err != nil {
			return errors.New("invalid trusted rules JSON")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing data in trusted rules JSON")
	}
	return nil
}

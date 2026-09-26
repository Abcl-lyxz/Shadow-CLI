// Package plugin exposes a deliberately narrow passive analyzer API. Signed
// data rules may inspect a bounded file prefix; plugins are never executed.
package plugin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const PrefixBytes = 4096

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9.-]{2,80}/[a-z][a-z0-9.-]{2,80}$`)
var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

type Rule struct {
	Offset int    `json:"offset"`
	Hex    string `json:"hex"`
	Label  string `json:"label"`
}

type Manifest struct {
	ID         string `json:"id"`
	Version    string `json:"version"`
	Purpose    string `json:"purpose"`
	Capability string `json:"capability"`
	Rules      []Rule `json:"rules"`
}

type signedManifest struct {
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

type Loaded struct {
	Manifest Manifest
	SHA256   string
	checks   []check
}

type check struct {
	offset int
	bytes  []byte
	label  string
}

func strict(data []byte, out any) error {
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func rejectDuplicateKeys(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid JSON key")
				}
				folded := strings.ToLower(key)
				if seen[folded] {
					return errors.New("duplicate plugin JSON key")
				}
				seen[folded] = true
				if err := walk(); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing plugin JSON")
	}
	return nil
}

// Load verifies the exact manifest payload against an explicitly supplied
// Ed25519 trust key. There is no executable, shell, or network capability.
func Load(manifestPath, publicKeyPath string) (Loaded, error) {
	f, err := os.Open(manifestPath)
	if err != nil {
		return Loaded{}, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, (32<<10)+1))
	if err != nil {
		return Loaded{}, err
	}
	if len(body) > 32<<10 {
		return Loaded{}, errors.New("plugin manifest exceeds 32 KiB")
	}
	var signed signedManifest
	if err := strict(body, &signed); err != nil {
		return Loaded{}, err
	}
	keyFile, err := os.Open(publicKeyPath)
	if err != nil {
		return Loaded{}, err
	}
	keyHex, err := io.ReadAll(io.LimitReader(keyFile, 129))
	closeErr := keyFile.Close()
	if err != nil {
		return Loaded{}, err
	}
	if closeErr != nil {
		return Loaded{}, closeErr
	}
	key, err := hex.DecodeString(string(bytes.TrimSpace(keyHex)))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return Loaded{}, errors.New("plugin trust key must be a 32-byte hex Ed25519 public key")
	}
	sig, err := hex.DecodeString(signed.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(key), signed.Payload, sig) {
		return Loaded{}, errors.New("plugin signature is invalid")
	}
	var m Manifest
	if err := strict(signed.Payload, &m); err != nil {
		return Loaded{}, err
	}
	if !idPattern.MatchString(m.ID) || !versionPattern.MatchString(m.Version) || m.Capability != "static-magic-v1" || len(m.Purpose) < 3 || len(m.Purpose) > 160 || len(m.Rules) == 0 || len(m.Rules) > 32 {
		return Loaded{}, errors.New("unsupported plugin metadata or capability")
	}
	for _, ch := range m.Purpose {
		if ch < 32 || ch > 126 {
			return Loaded{}, errors.New("plugin purpose must be printable ASCII")
		}
	}
	loaded := Loaded{Manifest: m}
	for _, rule := range m.Rules {
		pattern, err := hex.DecodeString(rule.Hex)
		if err != nil || len(pattern) == 0 || len(pattern) > 64 || rule.Offset < 0 || rule.Offset+len(pattern) > PrefixBytes || len(rule.Label) == 0 || len(rule.Label) > 80 {
			return Loaded{}, fmt.Errorf("invalid static magic rule")
		}
		for _, ch := range rule.Label {
			if ch < 32 || ch > 126 {
				return Loaded{}, errors.New("rule label must be printable ASCII")
			}
		}
		loaded.checks = append(loaded.checks, check{rule.Offset, pattern, rule.Label})
	}
	hash := sha256.Sum256(signed.Payload)
	loaded.SHA256 = hex.EncodeToString(hash[:])
	return loaded, nil
}

func (p Loaded) MatchPrefix(prefix []byte) []string {
	if len(prefix) > PrefixBytes {
		prefix = prefix[:PrefixBytes]
	}
	var labels []string
	for _, rule := range p.checks {
		if len(prefix) >= rule.offset+len(rule.bytes) && bytes.Equal(prefix[rule.offset:rule.offset+len(rule.bytes)], rule.bytes) {
			labels = append(labels, rule.label)
		}
	}
	return labels
}

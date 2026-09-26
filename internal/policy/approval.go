package policy

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// RuleApproval is a local operator attestation for one exact rule document.
// It is not a target-owner authorization or a network capability by itself.
type RuleApproval struct {
	Version     int    `json:"version"`
	Origin      string `json:"origin"`
	RulesSHA256 string `json:"rules_sha256"`
	IssuedAt    string `json:"issued_at"`
	ExpiresAt   string `json:"expires_at"`
	MAC         string `json:"mac"`
}

// VerifiedRules is created only after the local signature, digest, origin, and
// expiry have been checked. Its fields are private so callers cannot forge a
// run grant by constructing one directly.
type VerifiedRules struct {
	origin     string
	actions    []ActionRule
	digest     string
	approvalID string
	expiresAt  time.Time
}

func (v VerifiedRules) Origin() string        { return v.origin }
func (v VerifiedRules) Actions() []ActionRule { return append([]ActionRule(nil), v.actions...) }
func (v VerifiedRules) RulesSHA256() string   { return v.digest }
func (v VerifiedRules) ApprovalID() string    { return v.approvalID }
func (v VerifiedRules) ExpiresAt() time.Time  { return v.expiresAt }

// VerifyApprovedRules returns a value suitable for an immutable run binding.
// It does not establish authorization from the target owner.
func VerifyApprovedRules(rules TrustedRules, approval RuleApproval, key []byte, now time.Time) (VerifiedRules, error) {
	if err := VerifyRuleApproval(rules, approval, key, now); err != nil {
		return VerifiedRules{}, err
	}
	expires, _ := time.Parse(time.RFC3339, approval.ExpiresAt)
	sum := sha256.Sum256([]byte("shadow-rule-approval-id-v1\x00" + approval.MAC))
	return VerifiedRules{origin: rules.Origin, actions: append([]ActionRule(nil), rules.Actions...), digest: approval.RulesSHA256, approvalID: hex.EncodeToString(sum[:]), expiresAt: expires}, nil
}

// ParseRuleApproval refuses unknown, duplicate, and trailing JSON data.
func ParseRuleApproval(reader io.Reader) (RuleApproval, error) {
	data, err := io.ReadAll(io.LimitReader(reader, 4097))
	if err != nil || len(data) > 4096 || rejectDuplicateJSONKeys(data) != nil {
		return RuleApproval{}, errors.New("invalid rule approval document")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var approval RuleApproval
	if err := decoder.Decode(&approval); err != nil {
		return RuleApproval{}, errors.New("invalid rule approval document")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return RuleApproval{}, errors.New("trailing rule approval data")
	}
	return approval, nil
}

// TrustedRulesDigest hashes the normalized, validated document. The digest
// changes when an action, effect, cleanup contract, or action order changes.
func TrustedRulesDigest(rules TrustedRules) (string, error) {
	if rules.Version != 1 {
		return "", errors.New("unsupported trusted rules version")
	}
	scope, err := FromTarget(rules.Origin)
	if err != nil || scope.Origin != rules.Origin {
		return "", errors.New("invalid trusted rules origin")
	}
	encoded, err := json.Marshal(rules)
	if err != nil {
		return "", err
	}
	if _, err := ParseTrustedRules(bytes.NewReader(encoded), scope.Origin); err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("shadow-rules-v1\x00"), encoded...))
	return hex.EncodeToString(sum[:]), nil
}

func approvalMessage(a RuleApproval) []byte {
	return []byte("shadow-local-rule-approval-v1\x00" + a.Origin + "\x00" + a.RulesSHA256 + "\x00" + a.IssuedAt + "\x00" + a.ExpiresAt)
}

// SignRuleApproval is used only after a direct operator confirmation of the
// exact digest. The signing key belongs in a separate OS-keyring service.
func SignRuleApproval(rules TrustedRules, key []byte, now time.Time) (RuleApproval, error) {
	if len(key) != 32 {
		return RuleApproval{}, errors.New("rule approval key must be 32 bytes")
	}
	digest, err := TrustedRulesDigest(rules)
	if err != nil {
		return RuleApproval{}, err
	}
	now = now.UTC().Truncate(time.Second)
	a := RuleApproval{Version: 1, Origin: rules.Origin, RulesSHA256: digest, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339)}
	mac := hmac.New(sha256.New, key)
	mac.Write(approvalMessage(a))
	a.MAC = hex.EncodeToString(mac.Sum(nil))
	return a, nil
}

// VerifyRuleApproval checks the local attestation against the exact rules.
// A later run must still bind this approval to its immutable run snapshot.
func VerifyRuleApproval(rules TrustedRules, a RuleApproval, key []byte, now time.Time) error {
	if len(key) != 32 || a.Version != 1 || a.Origin != rules.Origin {
		return errors.New("rule approval is invalid")
	}
	digest, err := TrustedRulesDigest(rules)
	if err != nil || a.RulesSHA256 != digest {
		return errors.New("rule approval does not match the trusted rules")
	}
	issued, err := time.Parse(time.RFC3339, a.IssuedAt)
	if err != nil {
		return errors.New("rule approval issue time is invalid")
	}
	expires, err := time.Parse(time.RFC3339, a.ExpiresAt)
	if err != nil || !expires.After(issued) || expires.Sub(issued) > 24*time.Hour || now.Before(issued) || !now.Before(expires) {
		return errors.New("rule approval is expired or outside its issue window")
	}
	provided, err := hex.DecodeString(a.MAC)
	if err != nil || len(provided) != sha256.Size {
		return errors.New("rule approval signature is invalid")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(approvalMessage(a))
	if subtle.ConstantTimeCompare(provided, mac.Sum(nil)) != 1 {
		return errors.New("rule approval signature is invalid")
	}
	return nil
}

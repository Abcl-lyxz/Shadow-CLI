package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"shadow/internal/policy"
)

// ActionGrant records an exact trusted rule without retaining URL paths or queries.
type ActionGrant struct {
	Method           string        `json:"method"`
	URLSHA256        string        `json:"url_sha256"`
	Effect           policy.Effect `json:"effect"`
	Resource         string        `json:"resource,omitempty"`
	CleanupMethod    string        `json:"cleanup_method,omitempty"`
	CleanupURLSHA256 string        `json:"cleanup_url_sha256,omitempty"`
}

type RunSnapshot struct {
	RunID     string        `json:"run_id"`
	Origin    string        `json:"origin"`
	Actions   []ActionGrant `json:"actions"`
	CreatedAt time.Time     `json:"created_at"`
}

// AllowsAction matches a trusted rule against this run's immutable grant.
// Callers must validate the rule against the run scope before using it.
func (s RunSnapshot) AllowsAction(rule policy.ActionRule) bool {
	grant := grantFor(rule)
	for _, allowed := range s.Actions {
		if allowed == grant {
			return true
		}
	}
	return false
}

func grantFor(rule policy.ActionRule) ActionGrant {
	grant := ActionGrant{Method: rule.Method, URLSHA256: routeHash(rule.URL), Effect: rule.Effect}
	if rule.Effect == policy.EffectTestWrite {
		grant.Resource = rule.Resource
		grant.CleanupMethod = rule.CleanupMethod
		grant.CleanupURLSHA256 = routeHash(rule.CleanupURL)
	}
	return grant
}

// StartRun commits the scope, trusted action grants, and start event together.
// A run ID can be started only once; legacy runs without a snapshot cannot gain
// new write permissions after the fact.
func (s *Store) StartRun(ctx context.Context, runID string, scope policy.Scope, rules []policy.ActionRule) error {
	return s.startRun(ctx, runID, scope, rules, "", "", time.Time{})
}

// StartApprovedRun binds a locally verified rule approval to one immutable run
// before any target-capable dispatcher can be constructed. It does not grant
// public target access on its own.
func (s *Store) StartApprovedRun(ctx context.Context, runID string, verified policy.VerifiedRules) error {
	if verified.ApprovalID() == "" || verified.RulesSHA256() == "" || !time.Now().Before(verified.ExpiresAt()) {
		return errors.New("valid unexpired local rule approval required")
	}
	scope, err := policy.FromTarget(verified.Origin())
	if err != nil || scope.Origin != verified.Origin() {
		return errors.New("invalid approved run scope")
	}
	rules := verified.Actions()
	digest, err := policy.TrustedRulesDigest(policy.TrustedRules{Version: 1, Origin: scope.Origin, Actions: rules})
	if err != nil || digest != verified.RulesSHA256() {
		return errors.New("approved run rules do not match their digest")
	}
	return s.startRun(ctx, runID, scope, rules, verified.ApprovalID(), digest, verified.ExpiresAt())
}

func (s *Store) startRun(ctx context.Context, runID string, scope policy.Scope, rules []policy.ActionRule, approvalID, rulesDigest string, expiresAt time.Time) error {
	if runID == "" {
		return errors.New("run id required")
	}
	checked, err := policy.FromTarget(scope.Origin)
	if err != nil || checked.Origin != scope.Origin {
		return errors.New("invalid run scope")
	}
	if _, err := policy.NewActionPolicy(scope, rules); err != nil {
		return err
	}
	grants := make([]ActionGrant, 0, len(rules))
	for _, rule := range rules {
		grants = append(grants, grantFor(rule))
	}
	encoded, err := json.Marshal(grants)
	if err != nil {
		return err
	}
	unlock, err := s.beginProvenanceMutation(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM events WHERE run_id=?)", runID).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return errors.New("run already exists")
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO run_snapshots(run_id,origin,actions,created_at) VALUES(?,?,?,?)", runID, scope.Origin, encoded, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	if approvalID != "" {
		if _, err := tx.ExecContext(ctx, "INSERT INTO run_rule_approvals(run_id,approval_id,rules_sha256,expires_at) VALUES(?,?,?,?)", runID, approvalID, rulesDigest, expiresAt.UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO fixture_request_budget(run_id) VALUES(?)", runID); err != nil {
		return err
	}
	start := map[string]any{"scope": scope.Origin, "action_count": len(grants)}
	if approvalID != "" {
		start["rule_approval_id"] = approvalID
		start["rules_sha256"] = rulesDigest
		start["rule_approval_expires_at"] = expiresAt.UTC().Format(time.RFC3339)
	}
	if _, err := actionEvent(ctx, tx, runID, "started", start); err != nil {
		return err
	}
	return s.commitWithProvenance(ctx, tx, "run_start")
}

// RunRuleApproval returns only a digest reference and expiration, never the
// signed approval document or its key. Missing rows are unapproved runs.
func (s *Store) RunRuleApproval(ctx context.Context, runID string) (string, string, time.Time, error) {
	var approvalID, rulesDigest, expiry string
	if err := s.db.QueryRowContext(ctx, "SELECT approval_id,rules_sha256,expires_at FROM run_rule_approvals WHERE run_id=?", runID).Scan(&approvalID, &rulesDigest, &expiry); err != nil {
		return "", "", time.Time{}, err
	}
	var payload []byte
	if err := s.db.QueryRowContext(ctx, "SELECT payload FROM events WHERE run_id=? AND kind='started' ORDER BY id LIMIT 1", runID).Scan(&payload); err != nil {
		return "", "", time.Time{}, err
	}
	var started struct {
		ApprovalID string `json:"rule_approval_id"`
		RulesSHA   string `json:"rules_sha256"`
		ExpiresAt  string `json:"rule_approval_expires_at"`
	}
	if err := json.Unmarshal(payload, &started); err != nil || started.ApprovalID != approvalID || started.RulesSHA != rulesDigest || started.ExpiresAt != expiry {
		return "", "", time.Time{}, errors.New("run rule approval differs from the provenance-backed start event")
	}
	expiresAt, err := time.Parse(time.RFC3339, expiry)
	return approvalID, rulesDigest, expiresAt, err
}

func (s *Store) RunSnapshot(ctx context.Context, runID string) (RunSnapshot, error) {
	var snap RunSnapshot
	var actions []byte
	var created string
	err := s.db.QueryRowContext(ctx, "SELECT run_id,origin,actions,created_at FROM run_snapshots WHERE run_id=?", runID).Scan(&snap.RunID, &snap.Origin, &actions, &created)
	if err != nil {
		return RunSnapshot{}, err
	}
	if err := json.Unmarshal(actions, &snap.Actions); err != nil {
		return RunSnapshot{}, err
	}
	snap.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	return snap, err
}

// RecordFixtureNetworkDecision durably records a read policy check before an
// HTTP hop. Denied mutation attempts may also be recorded without a grant.
func (s *Store) RecordFixtureNetworkDecision(ctx context.Context, snapshot RunSnapshot, method, raw string, allowed bool) error {
	return s.recordFixtureNetworkDecision(ctx, snapshot, method, raw, allowed, 0, false, "", "")
}

// RecordApprovedReadDecision checks the local approval in the same transaction
// as the pre-dispatch decision event. Missing, changed, or expired approval
// metadata cannot produce an allowed decision.
func (s *Store) RecordApprovedReadDecision(ctx context.Context, snapshot RunSnapshot, raw string, allowed bool, approvalID, rulesDigest string) error {
	if approvalID == "" || rulesDigest == "" {
		return errors.New("approved read decision needs an approval binding")
	}
	return s.recordFixtureNetworkDecision(ctx, snapshot, http.MethodGet, raw, allowed, 0, false, approvalID, rulesDigest)
}

// RecordFixtureAuthDecision permits only an exact, snapshotted authentication
// action. It records a URL hash, never a credential or session value.
func (s *Store) RecordFixtureAuthDecision(ctx context.Context, snapshot RunSnapshot, raw string) error {
	return s.recordFixtureNetworkDecision(ctx, snapshot, http.MethodPost, raw, true, 0, true, "", "")
}

// RecordFixtureMutationDecision accepts a possible POST or attempted DELETE
// only when the matching test-action obligation is current in the same run.
func (s *Store) RecordFixtureMutationDecision(ctx context.Context, snapshot RunSnapshot, method, raw string, actionID int64) error {
	if method != http.MethodPost && method != http.MethodDelete || actionID <= 0 {
		return errors.New("invalid fixture mutation decision")
	}
	return s.recordFixtureNetworkDecision(ctx, snapshot, method, raw, true, actionID, false, "", "")
}

func (s *Store) recordFixtureNetworkDecision(ctx context.Context, snapshot RunSnapshot, method, raw string, allowed bool, actionID int64, auth bool, approvalID, rulesDigest string) error {
	if s == nil || snapshot.RunID == "" || raw == "" || (method != http.MethodGet && method != http.MethodPost && method != http.MethodDelete) || (allowed && method != http.MethodGet && actionID <= 0 && !auth) || (auth && (!allowed || method != http.MethodPost || actionID != 0)) {
		return errors.New("invalid fixture network decision")
	}
	digest := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(digest[:])
	actions, err := json.Marshal(snapshot.Actions)
	if err != nil {
		return err
	}
	unlock, err := s.beginProvenanceMutation(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM run_snapshots WHERE run_id=? AND origin=? AND actions=? AND created_at=?)", snapshot.RunID, snapshot.Origin, actions, snapshot.CreatedAt.Format(time.RFC3339Nano)).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return errors.New("fixture network decision has no current run snapshot")
	}
	if approvalID != "" {
		if method != http.MethodGet || actionID != 0 || auth {
			return errors.New("approval binding applies only to reads")
		}
		var recordedDigest, expiry string
		if err := tx.QueryRowContext(ctx, "SELECT rules_sha256,expires_at FROM run_rule_approvals WHERE run_id=? AND approval_id=?", snapshot.RunID, approvalID).Scan(&recordedDigest, &expiry); err != nil || recordedDigest != rulesDigest {
			return errors.New("approved read decision has no matching run approval")
		}
		expiresAt, err := time.Parse(time.RFC3339, expiry)
		if err != nil || !time.Now().Before(expiresAt) {
			return errors.New("approved read decision has expired")
		}
		var startPayload []byte
		if err := tx.QueryRowContext(ctx, "SELECT payload FROM events WHERE run_id=? AND kind='started' ORDER BY id LIMIT 1", snapshot.RunID).Scan(&startPayload); err != nil {
			return errors.New("approved read decision has no run start event")
		}
		var started struct {
			ApprovalID string `json:"rule_approval_id"`
			RulesSHA   string `json:"rules_sha256"`
			ExpiresAt  string `json:"rule_approval_expires_at"`
		}
		if err := json.Unmarshal(startPayload, &started); err != nil || started.ApprovalID != approvalID || started.RulesSHA != rulesDigest || started.ExpiresAt != expiry {
			return errors.New("approved read decision differs from its start event")
		}
	}
	if allowed {
		if method == http.MethodGet {
			granted := false
			for _, rule := range snapshot.Actions {
				if rule == (ActionGrant{Method: method, URLSHA256: hash, Effect: policy.EffectRead}) {
					granted = true
					break
				}
			}
			if !granted || actionID != 0 {
				return errors.New("fixture network decision lacks a read grant")
			}
		} else if auth {
			granted := false
			for _, rule := range snapshot.Actions {
				if rule == (ActionGrant{Method: http.MethodPost, URLSHA256: hash, Effect: policy.EffectAuth}) {
					granted = true
					break
				}
			}
			if !granted {
				return errors.New("fixture authentication is not in the run snapshot")
			}
		} else {
			var origin, resource, writeMethod, writeHash, cleanupMethod, cleanupHash, cleanupProtocol, status string
			if err := tx.QueryRowContext(ctx, "SELECT origin,resource,method,url_sha256,cleanup_method,cleanup_url_sha256,cleanup_protocol,status FROM test_actions WHERE id=? AND run_id=?", actionID, snapshot.RunID).Scan(&origin, &resource, &writeMethod, &writeHash, &cleanupMethod, &cleanupHash, &cleanupProtocol, &status); err != nil {
				return errors.New("fixture mutation has no matching journal action")
			}
			if origin != snapshot.Origin {
				return errors.New("fixture mutation origin differs from run scope")
			}
			granted := false
			for _, rule := range snapshot.Actions {
				if rule == (ActionGrant{Method: writeMethod, URLSHA256: writeHash, Effect: policy.EffectTestWrite, Resource: resource, CleanupMethod: cleanupMethod, CleanupURLSHA256: cleanupHash}) {
					granted = true
					break
				}
			}
			if !granted || method == http.MethodPost && (writeMethod != method || writeHash != hash || status != TestActionWritePossible || cleanupProtocol != FixtureMarkerProtocolV1 && cleanupProtocol != FixtureRecordProtocolV1) || method == http.MethodDelete && (cleanupMethod != method || cleanupHash != hash || status != TestActionCleanupAttempted || cleanupProtocol != FixtureMarkerProtocolV1 && cleanupProtocol != FixtureRecordProtocolV1 && cleanupProtocol != legacyCleanupProtocol) {
				return errors.New("fixture mutation is not granted in the current journal state")
			}
		}
	}
	payload := map[string]any{"method": method, "url_sha256": hash, "allowed": allowed}
	if actionID > 0 {
		payload["test_action_id"] = actionID
	}
	if _, err := actionEvent(ctx, tx, snapshot.RunID, "network_decision", payload); err != nil {
		return err
	}
	return s.commitWithProvenance(ctx, tx, "network_decision")
}

func snapshotGrants(ctx context.Context, tx *sql.Tx, runID string) (string, []ActionGrant, error) {
	var origin string
	var encoded []byte
	if err := tx.QueryRowContext(ctx, "SELECT origin,actions FROM run_snapshots WHERE run_id=?", runID).Scan(&origin, &encoded); err != nil {
		return "", nil, err
	}
	var grants []ActionGrant
	if err := json.Unmarshal(encoded, &grants); err != nil {
		return "", nil, err
	}
	return origin, grants, nil
}

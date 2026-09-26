package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"shadow/internal/policy"
)

const (
	TestActionPlanned          = "planned"
	TestActionWritePossible    = "write_may_have_happened"
	TestActionCleanupAttempted = "cleanup_attempted"
	TestActionCleanupFailed    = "cleanup_failed"
	TestActionCleanupObserved  = "cleanup_observed"
	TestActionFixtureVerified  = "fixture_cleanup_verified"
)

// TestAction contains only route hashes and a non-sensitive resource marker.
// cleanup_observed is not proof that the resource was removed.
type TestAction struct {
	ID                 int64  `json:"id"`
	RunID              string `json:"run_id"`
	Origin             string `json:"origin"`
	Resource           string `json:"resource"`
	Method             string `json:"method"`
	URLSHA256          string `json:"url_sha256"`
	CleanupMethod      string `json:"cleanup_method"`
	CleanupURLSHA256   string `json:"cleanup_url_sha256"`
	Status             string `json:"status"`
	PlannedEventID     int64  `json:"planned_event_id"`
	WriteEventID       int64  `json:"write_event_id"`
	CleanupEventID     int64  `json:"cleanup_event_id"`
	ObservationEventID int64  `json:"observation_event_id"`
	StateEventID       int64  `json:"state_event_id"`
	ReviewEventID      int64  `json:"review_event_id"`
	ReviewedStateID    int64  `json:"reviewed_state_event_id"`
}

func migrateTestActionState(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(test_actions)")
	if err != nil {
		return err
	}
	hasColumn := false
	for rows.Next() {
		var index, notNull, primary int
		var name, dataType string
		var defaultValue sql.NullString
		if err := rows.Scan(&index, &name, &dataType, &notNull, &defaultValue, &primary); err != nil {
			rows.Close()
			return err
		}
		if name == "state_event_id" {
			hasColumn = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if !hasColumn {
		if _, err := db.Exec("ALTER TABLE test_actions ADD COLUMN state_event_id INTEGER NOT NULL DEFAULT 0"); err != nil {
			return err
		}
	}
	legacy, err := db.Query("SELECT id,run_id,status FROM test_actions WHERE state_event_id=0")
	if err != nil {
		return err
	}
	type oldAction struct {
		id     int64
		runID  string
		status string
	}
	var pending []oldAction
	for legacy.Next() {
		var action oldAction
		if err := legacy.Scan(&action.id, &action.runID, &action.status); err != nil {
			legacy.Close()
			return err
		}
		pending = append(pending, action)
	}
	if err := legacy.Err(); err != nil {
		legacy.Close()
		return err
	}
	legacy.Close()
	if len(pending) == 0 {
		return nil
	}
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, action := range pending {
		eventID, err := actionEvent(ctx, tx, action.runID, "test_action_state_migrated", map[string]any{"test_action_id": action.id, "status": action.status})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE test_actions SET state_event_id=? WHERE id=? AND run_id=? AND state_event_id=0", eventID, action.id, action.runID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func routeHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func actionEvent(ctx context.Context, tx *sql.Tx, runID, kind string, payload any) (int64, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, "INSERT INTO events(run_id,at,kind,payload) VALUES(?,?,?,?)", runID, time.Now().UTC().Format(time.RFC3339Nano), kind, b)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// PlanTestWrite persists the cleanup obligation before any network action.
// Only a trusted runtime caller should construct the action policy.
func (s *Store) PlanTestWrite(ctx context.Context, runID string, decision policy.ActionDecision) (int64, error) {
	rule := decision.Rule
	u, err := url.Parse(rule.URL)
	if err != nil || u == nil || runID == "" || !decision.Allowed || rule.Effect != policy.EffectTestWrite {
		return 0, errors.New("allowed test write rule and run required")
	}
	scope, err := policy.FromTarget(rule.URL)
	if err != nil {
		return 0, err
	}
	validated, err := policy.NewActionPolicy(scope, []policy.ActionRule{rule})
	if err != nil || !validated.Classify(rule.Method, rule.URL).Allowed {
		return 0, errors.New("invalid test write plan")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	origin, grants, err := snapshotGrants(ctx, tx, runID)
	if err != nil {
		return 0, errors.New("run has no immutable action snapshot")
	}
	if origin != scope.Origin {
		return 0, errors.New("test write is outside the run snapshot scope")
	}
	granted := false
	for _, grant := range grants {
		if grant == grantFor(rule) && grant.Effect == policy.EffectTestWrite {
			granted = true
			break
		}
	}
	if !granted {
		return 0, errors.New("test write is not in the run action snapshot")
	}
	urlHash, cleanupHash := routeHash(rule.URL), routeHash(rule.CleanupURL)
	eventID, err := actionEvent(ctx, tx, runID, "test_write_planned", map[string]string{
		"origin": scope.Origin, "resource": rule.Resource, "method": rule.Method,
		"url_sha256": urlHash, "cleanup_method": rule.CleanupMethod, "cleanup_url_sha256": cleanupHash,
	})
	if err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, "INSERT INTO test_actions(run_id,origin,resource,method,url_sha256,cleanup_method,cleanup_url_sha256,status,planned_event_id,state_event_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
		runID, scope.Origin, rule.Resource, rule.Method, urlHash, rule.CleanupMethod, cleanupHash, TestActionPlanned, eventID, eventID)
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// MarkTestWritePossible must be called before dispatch, so a crash or timeout
// leaves a visible cleanup obligation even when the request outcome is unknown.
func (s *Store) MarkTestWritePossible(ctx context.Context, runID string, id int64) error {
	return s.advanceTestAction(ctx, runID, id, TestActionPlanned, TestActionWritePossible, "test_write_possible", "write_event_id", 0)
}

func (s *Store) MarkCleanupAttempted(ctx context.Context, runID string, id int64) error {
	return s.advanceTestAction(ctx, runID, id, TestActionWritePossible, TestActionCleanupAttempted, "cleanup_attempted", "cleanup_event_id", 0)
}

func (s *Store) MarkCleanupFailed(ctx context.Context, runID string, id int64) error {
	return s.advanceTestAction(ctx, runID, id, TestActionCleanupAttempted, TestActionCleanupFailed, "cleanup_failed", "", 0)
}

func (s *Store) RetryCleanup(ctx context.Context, runID string, id int64) error {
	return s.advanceTestAction(ctx, runID, id, TestActionCleanupFailed, TestActionCleanupAttempted, "cleanup_attempted", "cleanup_event_id", 0)
}

// RecordCleanupObservation links later encrypted fixture evidence to an
// attempt. It does not claim that the test resource is gone.
func (s *Store) RecordCleanupObservation(ctx context.Context, runID string, id, observationEventID int64) error {
	observation, err := s.observationInRun(ctx, runID, observationEventID)
	if err != nil {
		return errors.New("cleanup observation requires same-run authenticated evidence")
	}
	var origin string
	if err := s.db.QueryRowContext(ctx, "SELECT origin FROM test_actions WHERE id=? AND run_id=?", id, runID).Scan(&origin); err != nil || origin != observation.Origin {
		return errors.New("cleanup observation must match the test action origin")
	}
	return s.advanceTestAction(ctx, runID, id, TestActionCleanupAttempted, TestActionCleanupObserved, "cleanup_observed", "observation_event_id", observationEventID)
}

// VerifyFixtureCleanup recognizes only the local fixture's resource contract:
// a recorded GET showing the named marker present after the possible write,
// followed by a recorded GET showing it absent after the DELETE attempt. This
// does not establish cleanup semantics for an arbitrary target API.
func (s *Store) VerifyFixtureCleanup(ctx context.Context, runID string, id, beforeID int64, readURL string) error {
	if runID == "" || id <= 0 || beforeID <= 0 || readURL == "" {
		return errors.New("fixture cleanup verification inputs required")
	}
	var resource, origin, status string
	var writeID, cleanupID, afterID int64
	err := s.db.QueryRowContext(ctx, "SELECT resource,origin,status,write_event_id,cleanup_event_id,observation_event_id FROM test_actions WHERE id=? AND run_id=?", id, runID).Scan(&resource, &origin, &status, &writeID, &cleanupID, &afterID)
	if err != nil || status != TestActionCleanupObserved || !(writeID < beforeID && beforeID < cleanupID && cleanupID < afterID) {
		return errors.New("fixture cleanup evidence is missing or out of order")
	}
	snapshot, err := s.RunSnapshot(ctx, runID)
	if err != nil || snapshot.Origin != origin || !snapshot.AllowsAction(policy.ActionRule{URL: readURL, Method: "GET", Effect: policy.EffectRead}) {
		return errors.New("fixture verification read is not in the run snapshot")
	}
	scope, err := policy.FromTarget(readURL)
	if err != nil || scope.Origin != origin {
		return errors.New("fixture verification read is outside the run origin")
	}
	before, beforeRaw, err := s.ValidatedObservation(ctx, runID, beforeID)
	if err != nil {
		return errors.New("fixture presence evidence is invalid")
	}
	after, afterRaw, err := s.ValidatedObservation(ctx, runID, afterID)
	if err != nil {
		return errors.New("fixture absence evidence is invalid")
	}
	if !FixtureMarkerState(before, beforeRaw, readURL, resource, true) || !FixtureMarkerState(after, afterRaw, readURL, resource, false) {
		return errors.New("fixture resource state was not verified")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	eventID, err := actionEvent(ctx, tx, runID, "fixture_cleanup_verified", map[string]any{
		"test_action_id": id, "status": TestActionFixtureVerified,
		"presence_event_id": beforeID, "absence_event_id": afterID,
	})
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, "UPDATE test_actions SET status=?,state_event_id=? WHERE id=? AND run_id=? AND status=? AND observation_event_id=? AND write_event_id<? AND cleanup_event_id>? AND cleanup_event_id<?", TestActionFixtureVerified, eventID, id, runID, TestActionCleanupObserved, afterID, beforeID, beforeID, afterID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil || count != 1 {
		return errors.New("fixture cleanup state changed before verification")
	}
	return tx.Commit()
}

// FixtureMarkerState is the narrow JSON contract used by local cleanup fixtures.
func FixtureMarkerState(summary EvidenceSummary, raw RawHTTP, readURL, resource string, present bool) bool {
	if summary.Truncated || summary.ContentType != "application/json" || raw.RequestURL != readURL || raw.Method != "GET" {
		return false
	}
	if present && summary.Status != 200 || !present && summary.Status != 404 {
		return false
	}
	var state struct {
		Resource string `json:"resource"`
		Present  *bool  `json:"present"`
	}
	if err := json.Unmarshal(raw.Body, &state); err != nil || state.Present == nil {
		return false
	}
	return state.Resource == resource && *state.Present == present
}

func (s *Store) advanceTestAction(ctx context.Context, runID string, id int64, from, to, kind, column string, observationID int64) error {
	if runID == "" || id <= 0 {
		return errors.New("run and test action required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	eventID, err := actionEvent(ctx, tx, runID, kind, map[string]any{"test_action_id": id, "status": to})
	if err != nil {
		return err
	}
	query := "UPDATE test_actions SET status=?, state_event_id=? WHERE id=? AND run_id=? AND status=?"
	args := []any{to, eventID, id, runID, from}
	switch column {
	case "write_event_id", "cleanup_event_id":
		query = "UPDATE test_actions SET status=?, state_event_id=?, " + column + "=? WHERE id=? AND run_id=? AND status=?"
		args = []any{to, eventID, eventID, id, runID, from}
	case "observation_event_id":
		query = "UPDATE test_actions SET status=?, state_event_id=?, observation_event_id=? WHERE id=? AND run_id=? AND status=? AND cleanup_event_id<? AND EXISTS(SELECT 1 FROM evidence WHERE event_id=? AND run_id=?)"
		args = []any{to, eventID, observationID, id, runID, from, observationID, observationID, runID}
	case "":
	default:
		return errors.New("invalid test action transition")
	}
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("test action transition rejected")
	}
	return tx.Commit()
}

func (s *Store) TestActions(ctx context.Context, runID string) ([]TestAction, error) {
	if runID == "" {
		return nil, errors.New("run required")
	}
	rows, err := s.db.QueryContext(ctx, "SELECT a.id,a.run_id,a.origin,a.resource,a.method,a.url_sha256,a.cleanup_method,a.cleanup_url_sha256,a.status,a.planned_event_id,COALESCE(a.write_event_id,0),COALESCE(a.cleanup_event_id,0),COALESCE(a.observation_event_id,0),a.state_event_id,COALESCE(r.review_event_id,0),COALESCE(r.state_event_id,0) FROM test_actions a LEFT JOIN test_action_reviews r ON r.id=(SELECT MAX(id) FROM test_action_reviews WHERE action_id=a.id AND run_id=a.run_id) WHERE a.run_id=? ORDER BY a.id", runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TestAction
	for rows.Next() {
		var a TestAction
		if err := rows.Scan(&a.ID, &a.RunID, &a.Origin, &a.Resource, &a.Method, &a.URLSHA256, &a.CleanupMethod, &a.CleanupURLSHA256, &a.Status, &a.PlannedEventID, &a.WriteEventID, &a.CleanupEventID, &a.ObservationEventID, &a.StateEventID, &a.ReviewEventID, &a.ReviewedStateID); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ReviewTestAction records that a human inspected one exact journal state.
// This never clears the cleanup obligation or asserts semantic cleanup.
func (s *Store) ReviewTestAction(ctx context.Context, runID string, id, expectedStateEventID int64) error {
	if runID == "" || id <= 0 || expectedStateEventID <= 0 {
		return errors.New("run, action ID, and observed state event ID required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var status string
	var stateEventID int64
	if err := tx.QueryRowContext(ctx, "SELECT status,state_event_id FROM test_actions WHERE id=? AND run_id=?", id, runID).Scan(&status, &stateEventID); err != nil {
		return errors.New("test action not found in run")
	}
	if stateEventID != expectedStateEventID || status == TestActionPlanned {
		return errors.New("test action state changed or has no dispatched-write obligation")
	}
	var lastReview int64
	err = tx.QueryRowContext(ctx, "SELECT state_event_id FROM test_action_reviews WHERE action_id=? AND run_id=? ORDER BY id DESC LIMIT 1", id, runID).Scan(&lastReview)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if lastReview == stateEventID {
		return errors.New("this test action state was already reviewed")
	}
	eventID, err := actionEvent(ctx, tx, runID, "test_action_reviewed", map[string]any{"test_action_id": id, "state_event_id": stateEventID, "status": status})
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO test_action_reviews(run_id,action_id,state_event_id,review_event_id,status) VALUES(?,?,?,?,?)", runID, id, stateEventID, eventID, status); err != nil {
		return fmt.Errorf("record test action review: %w", err)
	}
	return tx.Commit()
}

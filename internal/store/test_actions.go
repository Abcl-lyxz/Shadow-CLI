package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	var exists bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM events WHERE run_id=?)", runID).Scan(&exists); err != nil {
		return 0, err
	}
	if !exists {
		return 0, errors.New("run not found")
	}
	urlHash, cleanupHash := routeHash(rule.URL), routeHash(rule.CleanupURL)
	eventID, err := actionEvent(ctx, tx, runID, "test_write_planned", map[string]string{
		"origin": scope.Origin, "resource": rule.Resource, "method": rule.Method,
		"url_sha256": urlHash, "cleanup_method": rule.CleanupMethod, "cleanup_url_sha256": cleanupHash,
	})
	if err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, "INSERT INTO test_actions(run_id,origin,resource,method,url_sha256,cleanup_method,cleanup_url_sha256,status,planned_event_id) VALUES(?,?,?,?,?,?,?,?,?)",
		runID, scope.Origin, rule.Resource, rule.Method, urlHash, rule.CleanupMethod, cleanupHash, TestActionPlanned, eventID)
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
	query := "UPDATE test_actions SET status=? WHERE id=? AND run_id=? AND status=?"
	args := []any{to, id, runID, from}
	switch column {
	case "write_event_id", "cleanup_event_id":
		query = "UPDATE test_actions SET status=?, " + column + "=? WHERE id=? AND run_id=? AND status=?"
		args = []any{to, eventID, id, runID, from}
	case "observation_event_id":
		query = "UPDATE test_actions SET status=?, observation_event_id=? WHERE id=? AND run_id=? AND status=? AND cleanup_event_id<? AND EXISTS(SELECT 1 FROM evidence WHERE event_id=? AND run_id=?)"
		args = []any{to, observationID, id, runID, from, observationID, observationID, runID}
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
	rows, err := s.db.QueryContext(ctx, "SELECT id,run_id,origin,resource,method,url_sha256,cleanup_method,cleanup_url_sha256,status,planned_event_id,COALESCE(write_event_id,0),COALESCE(cleanup_event_id,0),COALESCE(observation_event_id,0) FROM test_actions WHERE run_id=? ORDER BY id", runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TestAction
	for rows.Next() {
		var a TestAction
		if err := rows.Scan(&a.ID, &a.RunID, &a.Origin, &a.Resource, &a.Method, &a.URLSHA256, &a.CleanupMethod, &a.CleanupURLSHA256, &a.Status, &a.PlannedEventID, &a.WriteEventID, &a.CleanupEventID, &a.ObservationEventID); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

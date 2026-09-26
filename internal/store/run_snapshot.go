package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
	if _, err := actionEvent(ctx, tx, runID, "started", map[string]any{"scope": scope.Origin, "action_count": len(grants)}); err != nil {
		return err
	}
	return tx.Commit()
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

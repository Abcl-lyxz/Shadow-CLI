package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db           *sql.DB
	evidenceKey  []byte
	provenance   *Provenance
	provenanceMu sync.Mutex
}

type Event struct {
	ID      int64           `json:"id"`
	RunID   string          `json:"run_id"`
	At      time.Time       `json:"at"`
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}

type Run struct {
	ID     string    `json:"id"`
	LastAt time.Time `json:"last_at"`
	Events int       `json:"events"`
}

type Memory struct {
	ID            int64     `json:"id"`
	Scope         string    `json:"scope"`
	Agent         string    `json:"agent"`
	Topic         string    `json:"topic"`
	Summary       string    `json:"summary"`
	SourceEventID int64     `json:"source_event_id"`
	CreatedAt     time.Time `json:"created_at"`
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, q := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, at TEXT NOT NULL, kind TEXT NOT NULL, payload BLOB NOT NULL)",
		"CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id,id)",
		"CREATE TABLE IF NOT EXISTS run_snapshots (run_id TEXT PRIMARY KEY, origin TEXT NOT NULL, actions BLOB NOT NULL, created_at TEXT NOT NULL)",
		"CREATE TABLE IF NOT EXISTS run_rule_approvals (run_id TEXT PRIMARY KEY REFERENCES run_snapshots(run_id), approval_id TEXT NOT NULL, rules_sha256 TEXT NOT NULL, expires_at TEXT NOT NULL)",
		"CREATE TRIGGER IF NOT EXISTS immutable_run_rule_approval BEFORE UPDATE ON run_rule_approvals BEGIN SELECT RAISE(ABORT, 'run rule approval is immutable'); END",
		"CREATE TABLE IF NOT EXISTS fixture_request_budget (run_id TEXT PRIMARY KEY REFERENCES run_snapshots(run_id), ordinary_used INTEGER NOT NULL DEFAULT 0, cleanup_used INTEGER NOT NULL DEFAULT 0, last_request_ns INTEGER NOT NULL DEFAULT 0, lease_token TEXT NOT NULL DEFAULT '', lease_until_ns INTEGER NOT NULL DEFAULT 0)",
		"CREATE TRIGGER IF NOT EXISTS immutable_run_snapshot BEFORE UPDATE ON run_snapshots BEGIN SELECT RAISE(ABORT, 'run snapshot is immutable'); END",
		"CREATE TABLE IF NOT EXISTS memories (id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL, agent TEXT NOT NULL, topic TEXT NOT NULL, summary TEXT NOT NULL, source_event_id INTEGER NOT NULL REFERENCES events(id), created_at TEXT NOT NULL)",
		"CREATE INDEX IF NOT EXISTS idx_memories_scope ON memories(scope,id)",
		"CREATE TABLE IF NOT EXISTS evidence (event_id INTEGER PRIMARY KEY REFERENCES events(id), run_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, sha256 TEXT NOT NULL, created_at TEXT NOT NULL)",
		"CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, title TEXT NOT NULL, asset TEXT NOT NULL, claim_type TEXT NOT NULL, status TEXT NOT NULL, source_event_id INTEGER NOT NULL REFERENCES evidence(event_id), reproduction_event_id INTEGER REFERENCES evidence(event_id), created_at TEXT NOT NULL)",
		"CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id,id)",
		"CREATE TABLE IF NOT EXISTS finding_reviews (id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id INTEGER NOT NULL REFERENCES findings(id), run_id TEXT NOT NULL, review_event_id INTEGER NOT NULL UNIQUE REFERENCES events(id), poc_status TEXT NOT NULL, confidence TEXT NOT NULL, duplicate_of INTEGER REFERENCES findings(id), cvss_vector TEXT NOT NULL, cvss_score REAL, created_at TEXT NOT NULL)",
		"CREATE INDEX IF NOT EXISTS idx_finding_reviews_find ON finding_reviews(finding_id,id)",
		"CREATE TABLE IF NOT EXISTS verified_response_memory (finding_id INTEGER PRIMARY KEY REFERENCES findings(id), scope TEXT NOT NULL, source_event_id INTEGER NOT NULL REFERENCES evidence(event_id), repeat_event_id INTEGER NOT NULL REFERENCES evidence(event_id), verification_event_id INTEGER NOT NULL REFERENCES events(id), confidence TEXT NOT NULL CHECK(confidence='reproduced_response'), expires_at TEXT NOT NULL, created_at TEXT NOT NULL)",
		"CREATE INDEX IF NOT EXISTS idx_verified_memory_scope ON verified_response_memory(scope,expires_at)",
		"CREATE TABLE IF NOT EXISTS agent_plans (run_id TEXT PRIMARY KEY REFERENCES run_snapshots(run_id), prompt_sha256 TEXT NOT NULL, route BLOB NOT NULL, budget BLOB NOT NULL, created_at TEXT NOT NULL)",
		"CREATE TRIGGER IF NOT EXISTS immutable_agent_plan BEFORE UPDATE ON agent_plans BEGIN SELECT RAISE(ABORT, 'agent plan is immutable'); END",
		"CREATE TABLE IF NOT EXISTS agent_jobs (run_id TEXT NOT NULL REFERENCES agent_plans(run_id), role TEXT NOT NULL, status TEXT NOT NULL, phase TEXT NOT NULL DEFAULT '', step INTEGER NOT NULL DEFAULT 0, input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0, cost_microusd INTEGER NOT NULL DEFAULT 0, tool_calls INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL, PRIMARY KEY(run_id,role))",
		"CREATE TABLE IF NOT EXISTS test_actions (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, origin TEXT NOT NULL, resource TEXT NOT NULL, method TEXT NOT NULL, url_sha256 TEXT NOT NULL, cleanup_method TEXT NOT NULL, cleanup_url_sha256 TEXT NOT NULL, cleanup_protocol TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, planned_event_id INTEGER NOT NULL REFERENCES events(id), write_event_id INTEGER REFERENCES events(id), cleanup_event_id INTEGER REFERENCES events(id), observation_event_id INTEGER REFERENCES evidence(event_id), state_event_id INTEGER NOT NULL DEFAULT 0)",
		"CREATE INDEX IF NOT EXISTS idx_test_actions_run ON test_actions(run_id,id)",
		"CREATE TABLE IF NOT EXISTS test_action_reviews (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, action_id INTEGER NOT NULL REFERENCES test_actions(id), state_event_id INTEGER NOT NULL REFERENCES events(id), review_event_id INTEGER NOT NULL REFERENCES events(id), status TEXT NOT NULL)",
		"CREATE INDEX IF NOT EXISTS idx_test_action_reviews_action ON test_action_reviews(action_id,id)",
	} {
		if _, err := db.Exec(q); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err := migrateTestActionState(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Append(ctx context.Context, runID, kind string, payload any) error {
	_, err := s.AppendWithID(ctx, runID, kind, payload)
	return err
}

func (s *Store) AppendWithID(ctx context.Context, runID, kind string, payload any) (int64, error) {
	if runID == "" || kind == "" {
		return 0, errors.New("run id and kind required")
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	unlock, err := s.beginProvenanceMutation(ctx)
	if err != nil {
		return 0, err
	}
	defer unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "INSERT INTO events(run_id,at,kind,payload) VALUES(?,?,?,?)", runID, time.Now().UTC().Format(time.RFC3339Nano), kind, b)
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	if err := s.commitWithProvenance(ctx, tx, "event"); err != nil {
		return 0, err
	}
	return id, nil
}

func (s *Store) Events(ctx context.Context, runID string) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id,run_id,at,kind,payload FROM events WHERE run_id=? ORDER BY id", runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var at string
		if err := rows.Scan(&e.ID, &e.RunID, &at, &e.Kind, &e.Payload); err != nil {
			return nil, err
		}
		e.At, err = time.Parse(time.RFC3339Nano, at)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) EventInRun(ctx context.Context, runID string, eventID int64) (Event, error) {
	var e Event
	var at string
	err := s.db.QueryRowContext(ctx, "SELECT id,run_id,at,kind,payload FROM events WHERE id=? AND run_id=?", eventID, runID).Scan(&e.ID, &e.RunID, &at, &e.Kind, &e.Payload)
	if err != nil {
		return Event{}, err
	}
	e.At, err = time.Parse(time.RFC3339Nano, at)
	return e, err
}

func (s *Store) Runs(ctx context.Context, limit int) ([]Run, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, "SELECT run_id,MAX(at),COUNT(*) FROM events GROUP BY run_id ORDER BY MAX(at) DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		var run Run
		var at string
		if err := rows.Scan(&run.ID, &at, &run.Events); err != nil {
			return nil, err
		}
		run.LastAt, err = time.Parse(time.RFC3339Nano, at)
		if err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, rows.Err()
}

func (s *Store) Remember(ctx context.Context, scope, runID, agent, topic, summary string, sourceEventID int64) error {
	if scope == "" || runID == "" || agent == "" || topic == "" || summary == "" || sourceEventID <= 0 {
		return errors.New("memory requires scope, run, agent, topic, summary, and source event")
	}
	if len(summary) > 800 || len(topic) > 80 {
		return errors.New("memory exceeds concise-note limit")
	}
	result, err := s.db.ExecContext(ctx,
		"INSERT INTO memories(scope,agent,topic,summary,source_event_id,created_at) SELECT ?,?,?,?,?,? FROM events WHERE id=? AND run_id=? AND kind IN ('tool','observation')",
		scope, agent, topic, summary, sourceEventID, time.Now().UTC().Format(time.RFC3339Nano), sourceEventID, runID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("source event is not a tool observation in this run")
	}
	return nil
}

func (s *Store) Recall(ctx context.Context, scope string, limit int) ([]Memory, error) {
	if scope == "" {
		return nil, errors.New("scope required")
	}
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	rows, err := s.db.QueryContext(ctx,
		"SELECT id,scope,agent,topic,summary,source_event_id,created_at FROM memories WHERE scope=? ORDER BY id DESC LIMIT ?", scope, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Memory
	for rows.Next() {
		var m Memory
		var created string
		if err := rows.Scan(&m.ID, &m.Scope, &m.Agent, &m.Topic, &m.Summary, &m.SourceEventID, &created); err != nil {
			return nil, err
		}
		m.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// PurgeRun removes one complete run and its evidence, findings, and memories.
// An unresolved test-write obligation prevents deletion, even with explicit
// confirmation. It is never called automatically.
func (s *Store) PurgeRun(ctx context.Context, runID string) error {
	return s.purgeRun(ctx, runID, nil)
}

func (s *Store) purgeRun(ctx context.Context, runID string, cutoff *time.Time) error {
	if runID == "" {
		return errors.New("run id required")
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
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM events WHERE run_id=?", runID).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		return errors.New("run not found")
	}
	if cutoff != nil {
		var latest string
		if err := tx.QueryRowContext(ctx, "SELECT MAX(at) FROM events WHERE run_id=?", runID).Scan(&latest); err != nil {
			return err
		}
		at, err := time.Parse(time.RFC3339Nano, latest)
		if err != nil {
			return err
		}
		if !at.Before(*cutoff) {
			return errRunNotExpired
		}
	}
	var unresolved int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM test_actions WHERE run_id=? AND status NOT IN (?,?)", runID, TestActionPlanned, TestActionFixtureVerified).Scan(&unresolved); err != nil {
		return err
	}
	if unresolved != 0 {
		return errUnresolvedCleanup
	}
	var unfinishedAgents int
	if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM agent_jobs WHERE run_id=? AND status IN ('pending','running','interrupted')", runID).Scan(&unfinishedAgents); err != nil {
		return err
	}
	if unfinishedAgents != 0 {
		return errUnresolvedAgentJob
	}
	var leaseToken string
	var leaseUntilNS int64
	err = tx.QueryRowContext(ctx, "SELECT lease_token,lease_until_ns FROM fixture_request_budget WHERE run_id=?", runID).Scan(&leaseToken, &leaseUntilNS)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && leaseToken != "" && leaseUntilNS > time.Now().UnixNano() {
		return errActiveFixtureRequest
	}
	for _, query := range []string{
		"DELETE FROM agent_jobs WHERE run_id=?",
		"DELETE FROM agent_plans WHERE run_id=?",
		"DELETE FROM memories WHERE source_event_id IN (SELECT id FROM events WHERE run_id=?)",
		"DELETE FROM verified_response_memory WHERE finding_id IN (SELECT id FROM findings WHERE run_id=?)",
		"DELETE FROM finding_reviews WHERE run_id=?",
		"DELETE FROM findings WHERE run_id=?",
		"DELETE FROM test_action_reviews WHERE run_id=?",
		"DELETE FROM test_actions WHERE run_id=?",
		"DELETE FROM evidence WHERE run_id=?",
		"DELETE FROM fixture_request_budget WHERE run_id=?",
		"DELETE FROM run_rule_approvals WHERE run_id=?",
		"DELETE FROM run_snapshots WHERE run_id=?",
		"DELETE FROM events WHERE run_id=?",
	} {
		if _, err := tx.ExecContext(ctx, query, runID); err != nil {
			return err
		}
	}
	return s.commitWithProvenance(ctx, tx, "purge_run")
}

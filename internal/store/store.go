package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db          *sql.DB
	evidenceKey []byte
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
		"CREATE TABLE IF NOT EXISTS memories (id INTEGER PRIMARY KEY AUTOINCREMENT, scope TEXT NOT NULL, agent TEXT NOT NULL, topic TEXT NOT NULL, summary TEXT NOT NULL, source_event_id INTEGER NOT NULL REFERENCES events(id), created_at TEXT NOT NULL)",
		"CREATE INDEX IF NOT EXISTS idx_memories_scope ON memories(scope,id)",
		"CREATE TABLE IF NOT EXISTS evidence (event_id INTEGER PRIMARY KEY REFERENCES events(id), run_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, sha256 TEXT NOT NULL, created_at TEXT NOT NULL)",
		"CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, title TEXT NOT NULL, asset TEXT NOT NULL, claim_type TEXT NOT NULL, status TEXT NOT NULL, source_event_id INTEGER NOT NULL REFERENCES evidence(event_id), reproduction_event_id INTEGER REFERENCES evidence(event_id), created_at TEXT NOT NULL)",
		"CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id,id)",
		"CREATE TABLE IF NOT EXISTS test_actions (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, origin TEXT NOT NULL, resource TEXT NOT NULL, method TEXT NOT NULL, url_sha256 TEXT NOT NULL, cleanup_method TEXT NOT NULL, cleanup_url_sha256 TEXT NOT NULL, status TEXT NOT NULL, planned_event_id INTEGER NOT NULL REFERENCES events(id), write_event_id INTEGER REFERENCES events(id), cleanup_event_id INTEGER REFERENCES events(id), observation_event_id INTEGER REFERENCES evidence(event_id))",
		"CREATE INDEX IF NOT EXISTS idx_test_actions_run ON test_actions(run_id,id)",
	} {
		if _, err := db.Exec(q); err != nil {
			db.Close()
			return nil, err
		}
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
	result, err := s.db.ExecContext(ctx, "INSERT INTO events(run_id,at,kind,payload) VALUES(?,?,?,?)", runID, time.Now().UTC().Format(time.RFC3339Nano), kind, b)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
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
// It is never called automatically; callers must obtain explicit confirmation.
func (s *Store) PurgeRun(ctx context.Context, runID string) error {
	if runID == "" {
		return errors.New("run id required")
	}
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
	for _, query := range []string{
		"DELETE FROM memories WHERE source_event_id IN (SELECT id FROM events WHERE run_id=?)",
		"DELETE FROM findings WHERE run_id=?",
		"DELETE FROM test_actions WHERE run_id=?",
		"DELETE FROM evidence WHERE run_id=?",
		"DELETE FROM events WHERE run_id=?",
	} {
		if _, err := tx.ExecContext(ctx, query, runID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

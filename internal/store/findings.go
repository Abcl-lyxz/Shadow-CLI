package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const (
	ClaimSecurityHypothesis  = "security_hypothesis"
	ClaimResponseObservation = "response_observation"
)

type Finding struct {
	ID                  int64     `json:"id"`
	RunID               string    `json:"run_id"`
	Title               string    `json:"title"`
	Asset               string    `json:"asset"`
	ClaimType           string    `json:"claim_type"`
	Status              string    `json:"status"`
	SourceEventID       int64     `json:"source_event_id"`
	ReproductionEventID int64     `json:"reproduction_event_id,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
}

// CreateFinding requires encrypted source evidence in the same run. A security
// claim remains a hypothesis; response observations can later be reproduced.
func (s *Store) CreateFinding(ctx context.Context, runID, title, asset, claimType string, sourceEventID int64) (int64, error) {
	if runID == "" || len(title) == 0 || len(title) > 160 || len(asset) == 0 || len(asset) > 300 || sourceEventID <= 0 || (claimType != ClaimSecurityHypothesis && claimType != ClaimResponseObservation) {
		return 0, errors.New("invalid finding")
	}
	summary, err := s.observationInRun(ctx, runID, sourceEventID)
	if err != nil {
		return 0, errors.New("finding requires an evidence-backed observation in this run")
	}
	if asset != summary.Origin {
		return 0, errors.New("finding asset must match observed origin")
	}
	if _, err := s.RawEvidence(ctx, runID, sourceEventID); err != nil {
		return 0, errors.New("source evidence is unavailable or tampered")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	at := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := tx.ExecContext(ctx, "INSERT INTO findings(run_id,title,asset,claim_type,status,source_event_id,created_at) VALUES(?,?,?,?,?,?,?)", runID, title, asset, claimType, "hypothesis", sourceEventID, at)
	if err != nil {
		return 0, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO events(run_id,at,kind,payload) VALUES(?,?,?,?)", runID, at, "finding_created", []byte(fmt.Sprintf(`{"finding_id":%d}`, id))); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

// VerifyResponseFinding confirms only that a later, independently recorded
// GET produced the same response bytes and status. It cannot verify a security
// vulnerability or impact claim.
func (s *Store) VerifyResponseFinding(ctx context.Context, runID string, findingID, reproductionEventID int64) error {
	if runID == "" || findingID <= 0 || reproductionEventID <= 0 {
		return errors.New("run, finding, and reproduction required")
	}
	var sourceID int64
	var claimType, status, createdAt string
	err := s.db.QueryRowContext(ctx, "SELECT source_event_id,claim_type,status,created_at FROM findings WHERE id=? AND run_id=?", findingID, runID).Scan(&sourceID, &claimType, &status, &createdAt)
	if err != nil {
		return err
	}
	if claimType != ClaimResponseObservation || status != "hypothesis" || reproductionEventID <= sourceID {
		return errors.New("finding is not eligible for response reproduction")
	}
	var creationEventID int64
	err = s.db.QueryRowContext(ctx, "SELECT id FROM events WHERE run_id=? AND kind='finding_created' AND payload=?", runID, []byte(fmt.Sprintf(`{"finding_id":%d}`, findingID))).Scan(&creationEventID)
	if err == nil {
		if reproductionEventID <= creationEventID {
			return errors.New("reproduction must be recorded after finding creation in the same run")
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		// Older databases predate the durable creation event.
		var reproducedAt string
		if err := s.db.QueryRowContext(ctx, "SELECT at FROM events WHERE id=? AND run_id=?", reproductionEventID, runID).Scan(&reproducedAt); err != nil {
			return errors.New("reproduction must be recorded after finding creation in the same run")
		}
		createdTime, err := time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			return err
		}
		reproducedTime, err := time.Parse(time.RFC3339Nano, reproducedAt)
		if err != nil || !reproducedTime.After(createdTime) {
			return errors.New("reproduction must be recorded after finding creation in the same run")
		}
	} else {
		return err
	}
	source, err := s.observationInRun(ctx, runID, sourceID)
	if err != nil {
		return err
	}
	repeat, err := s.observationInRun(ctx, runID, reproductionEventID)
	if err != nil {
		return errors.New("reproduction requires an evidence-backed observation in this run")
	}
	if source.Origin != repeat.Origin || source.URLSHA256 != repeat.URLSHA256 || source.Status != repeat.Status || source.SHA256 != repeat.SHA256 || source.Bytes != repeat.Bytes || source.Truncated || repeat.Truncated {
		return errors.New("reproduction differs from source or is truncated")
	}
	if _, err := s.RawEvidence(ctx, runID, sourceID); err != nil {
		return errors.New("source evidence is unavailable or tampered")
	}
	if _, err := s.RawEvidence(ctx, runID, reproductionEventID); err != nil {
		return errors.New("reproduction evidence is unavailable or tampered")
	}
	result, err := s.db.ExecContext(ctx, "UPDATE findings SET status='verified', reproduction_event_id=? WHERE id=? AND run_id=? AND status='hypothesis'", reproductionEventID, findingID, runID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("finding status changed")
	}
	return nil
}

func (s *Store) Findings(ctx context.Context, runID string) ([]Finding, error) {
	if runID == "" {
		return nil, errors.New("run id required")
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,run_id,title,asset,claim_type,status,source_event_id,reproduction_event_id,created_at FROM findings WHERE run_id=? ORDER BY id", runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		var repeat sql.NullInt64
		var at string
		if err := rows.Scan(&f.ID, &f.RunID, &f.Title, &f.Asset, &f.ClaimType, &f.Status, &f.SourceEventID, &repeat, &at); err != nil {
			return nil, err
		}
		if repeat.Valid {
			f.ReproductionEventID = repeat.Int64
		}
		f.CreatedAt, err = time.Parse(time.RFC3339Nano, at)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

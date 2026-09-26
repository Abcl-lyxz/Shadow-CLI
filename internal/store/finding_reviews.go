package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	gocvss40 "github.com/pandatix/go-cvss/40"
)

// FindingReview records an operator's bounded assessment. A response match is
// never evidence that a security vulnerability or its impact was verified.
type FindingReview struct {
	FindingID     int64     `json:"finding_id"`
	ReviewEventID int64     `json:"review_event_id"`
	PoCStatus     string    `json:"poc_status"`
	Confidence    string    `json:"confidence"`
	DuplicateOf   int64     `json:"duplicate_of,omitempty"`
	CVSSVector    string    `json:"cvss_vector,omitempty"`
	CVSSScore     *float64  `json:"cvss_score,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// ReviewFinding appends a new review and event atomically. The only supported
// PoC reproduction here is an independently matched HTTP response observation.
func (s *Store) ReviewFinding(ctx context.Context, runID string, findingID int64, poc, confidence string, duplicateOf int64, vector string) (FindingReview, error) {
	var out FindingReview
	if runID == "" || findingID <= 0 || duplicateOf < 0 || (poc != "not_attempted" && poc != "blocked" && poc != "response_reproduced") || (confidence != "low" && confidence != "medium" && confidence != "high") {
		return out, errors.New("invalid finding review")
	}
	if len(vector) > 250 {
		return out, errors.New("CVSS vector is too long")
	}
	if vector != "" {
		cvss, err := gocvss40.ParseVector(vector)
		if err != nil || cvss.Vector() != vector {
			return out, errors.New("invalid CVSS v4 vector")
		}
		score := cvss.Score()
		out.CVSSScore = &score
		out.CVSSVector = vector
	}
	unlock, err := s.beginProvenanceMutation(ctx)
	if err != nil {
		return out, err
	}
	defer unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var claim, status string
	var sourceID, repeatID sql.NullInt64
	if err := tx.QueryRowContext(ctx, "SELECT claim_type,status,source_event_id,reproduction_event_id FROM findings WHERE id=? AND run_id=?", findingID, runID).Scan(&claim, &status, &sourceID, &repeatID); err != nil {
		return out, err
	}
	if poc == "response_reproduced" && (claim != ClaimResponseObservation || status != "verified" || !repeatID.Valid) {
		return out, errors.New("reproduced response requires independent evidence; it cannot verify a vulnerability")
	}
	if claim != ClaimSecurityHypothesis && vector != "" {
		return out, errors.New("CVSS applies only to a security hypothesis")
	}
	if duplicateOf != 0 {
		if duplicateOf >= findingID {
			return out, errors.New("duplicate must refer to an earlier finding")
		}
		var otherClaim string
		if err := tx.QueryRowContext(ctx, "SELECT claim_type FROM findings WHERE id=? AND run_id=?", duplicateOf, runID).Scan(&otherClaim); err != nil {
			return out, errors.New("duplicate target must be in the same run")
		}
		if otherClaim != claim {
			return out, errors.New("duplicate target has a different claim type")
		}
		var parent int64
		if err := tx.QueryRowContext(ctx, "SELECT COALESCE(duplicate_of,0) FROM finding_reviews WHERE finding_id=? ORDER BY id DESC LIMIT 1", duplicateOf).Scan(&parent); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return out, err
		}
		if parent != 0 {
			return out, errors.New("duplicate target must be canonical")
		}
	}
	at := time.Now().UTC()
	out = FindingReview{FindingID: findingID, PoCStatus: poc, Confidence: confidence, DuplicateOf: duplicateOf, CVSSVector: vector, CVSSScore: out.CVSSScore, CreatedAt: at}
	eventID, err := actionEvent(ctx, tx, runID, "finding_reviewed", map[string]any{"finding_id": findingID, "poc_status": poc, "confidence": confidence, "duplicate_of": duplicateOf, "cvss_vector": vector, "cvss_score": out.CVSSScore, "source_event_id": sourceID.Int64, "reproduction_event_id": repeatID.Int64})
	if err != nil {
		return FindingReview{}, err
	}
	out.ReviewEventID = eventID
	if _, err := tx.ExecContext(ctx, "INSERT INTO finding_reviews(finding_id,run_id,review_event_id,poc_status,confidence,duplicate_of,cvss_vector,cvss_score,created_at) VALUES(?,?,?,?,?,?,?,?,?)", findingID, runID, eventID, poc, confidence, sql.NullInt64{Int64: duplicateOf, Valid: duplicateOf != 0}, vector, sql.NullFloat64{Float64: derefScore(out.CVSSScore), Valid: out.CVSSScore != nil}, at.Format(time.RFC3339Nano)); err != nil {
		return FindingReview{}, err
	}
	if err := s.commitWithProvenance(ctx, tx, "finding_reviewed"); err != nil {
		return FindingReview{}, err
	}
	return out, nil
}

func derefScore(score *float64) float64 {
	if score == nil {
		return 0
	}
	return *score
}

func (s *Store) FindingReviews(ctx context.Context, runID string) (map[int64]FindingReview, error) {
	if runID == "" {
		return nil, errors.New("run id required")
	}
	rows, err := s.db.QueryContext(ctx, "SELECT finding_id,review_event_id,poc_status,confidence,COALESCE(duplicate_of,0),cvss_vector,cvss_score,created_at FROM finding_reviews WHERE run_id=? ORDER BY id", runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]FindingReview{}
	for rows.Next() {
		var r FindingReview
		var score sql.NullFloat64
		var at string
		if err := rows.Scan(&r.FindingID, &r.ReviewEventID, &r.PoCStatus, &r.Confidence, &r.DuplicateOf, &r.CVSSVector, &score, &at); err != nil {
			return nil, err
		}
		if score.Valid {
			r.CVSSScore = &score.Float64
		}
		if r.CVSSVector != "" {
			cvss, parseErr := gocvss40.ParseVector(r.CVSSVector)
			if parseErr != nil || !score.Valid || cvss.Score() != score.Float64 {
				return nil, errors.New("finding review CVSS score does not match its vector")
			}
		} else if score.Valid {
			return nil, errors.New("finding review has a score without a vector")
		}
		if r.CreatedAt, err = time.Parse(time.RFC3339Nano, at); err != nil {
			return nil, fmt.Errorf("invalid review time: %w", err)
		}
		out[r.FindingID] = r
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, r := range out {
		event, eventErr := s.EventInRun(ctx, runID, r.ReviewEventID)
		if eventErr != nil || event.Kind != "finding_reviewed" {
			return nil, errors.New("finding review event is missing or changed")
		}
		var recorded struct {
			FindingID   int64    `json:"finding_id"`
			PoCStatus   string   `json:"poc_status"`
			Confidence  string   `json:"confidence"`
			DuplicateOf int64    `json:"duplicate_of"`
			CVSSVector  string   `json:"cvss_vector"`
			CVSSScore   *float64 `json:"cvss_score"`
		}
		if json.Unmarshal(event.Payload, &recorded) != nil || recorded.FindingID != r.FindingID || recorded.PoCStatus != r.PoCStatus || recorded.Confidence != r.Confidence || recorded.DuplicateOf != r.DuplicateOf || recorded.CVSSVector != r.CVSSVector || !equalScore(recorded.CVSSScore, r.CVSSScore) {
			return nil, errors.New("finding review differs from recorded event")
		}
	}
	return out, nil
}

func equalScore(a, b *float64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

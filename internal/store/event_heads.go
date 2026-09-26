package store

import (
	"context"
	"errors"
	"time"
)

// EventHeads reads only bounded event metadata for operator trace views.
// Historic payloads never leave SQLite through this method.
func (s *Store) EventHeads(ctx context.Context, runID string, limit int) ([]Event, error) {
	if runID == "" || limit < 1 || limit > 200 {
		return nil, errors.New("run and bounded event limit required")
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,run_id,at,kind FROM events WHERE run_id=? ORDER BY id DESC LIMIT ?", runID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var reversed []Event
	for rows.Next() {
		var e Event
		var at string
		if err := rows.Scan(&e.ID, &e.RunID, &at, &e.Kind); err != nil {
			return nil, err
		}
		e.At, err = time.Parse(time.RFC3339Nano, at)
		if err != nil {
			return nil, err
		}
		reversed = append(reversed, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	return reversed, nil
}

package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

const fixtureOrdinaryRequests = 16
const fixtureCleanupRequests = 4
const fixtureLeaseLifetime = 30 * time.Second

var errActiveFixtureRequest = errors.New("run has an active fixture network request")

// ReserveFixtureRequest charges one HTTP hop to a durable run budget before
// dispatch. Cleanup has reserved capacity, while both lanes share one rate
// interval and one in-flight lease. Missing budget rows fail closed, including
// runs started before this policy was added.
func (s *Store) ReserveFixtureRequest(ctx context.Context, runID string, cleanup bool, interval time.Duration) (string, error) {
	if runID == "" || interval <= 0 {
		return "", errors.New("fixture request needs a run and positive interval")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	token := hex.EncodeToString(random[:])
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return "", err
		}
		var ordinary, reserved, lastNS, leaseUntilNS int64
		var activeToken string
		err = tx.QueryRowContext(ctx, "SELECT ordinary_used,cleanup_used,last_request_ns,lease_token,lease_until_ns FROM fixture_request_budget WHERE run_id=?", runID).Scan(&ordinary, &reserved, &lastNS, &activeToken, &leaseUntilNS)
		if err != nil {
			tx.Rollback()
			if errors.Is(err, sql.ErrNoRows) {
				return "", errors.New("fixture run has no request budget")
			}
			return "", err
		}
		limit := int64(fixtureOrdinaryRequests)
		used := ordinary
		column := "ordinary_used"
		if cleanup {
			limit, used, column = fixtureCleanupRequests, reserved, "cleanup_used"
		}
		if used >= limit {
			tx.Rollback()
			return "", errors.New("fixture run request budget exhausted")
		}
		now := time.Now().UnixNano()
		readyAt := lastNS + int64(interval)
		if activeToken != "" && leaseUntilNS > readyAt {
			readyAt = leaseUntilNS
		}
		if now < readyAt {
			tx.Rollback()
			wait := time.Duration(readyAt - now)
			if wait > 50*time.Millisecond {
				wait = 50 * time.Millisecond
			}
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return "", ctx.Err()
			}
			continue
		}
		query := "UPDATE fixture_request_budget SET " + column + "=" + column + "+1,last_request_ns=?,lease_token=?,lease_until_ns=? WHERE run_id=? AND lease_token=? AND " + column + "<?"
		result, err := tx.ExecContext(ctx, query, now, token, now+int64(fixtureLeaseLifetime), runID, activeToken, limit)
		if err != nil {
			tx.Rollback()
			return "", err
		}
		updated, err := result.RowsAffected()
		if err != nil || updated != 1 {
			tx.Rollback()
			return "", errors.New("fixture request reservation raced with another writer")
		}
		if err := tx.Commit(); err != nil {
			return "", err
		}
		return token, nil
	}
}

// ReleaseFixtureRequest frees concurrency, never the already spent budget.
func (s *Store) ReleaseFixtureRequest(ctx context.Context, runID, token string) error {
	if runID == "" || token == "" {
		return errors.New("fixture request lease required")
	}
	_, err := s.db.ExecContext(ctx, "UPDATE fixture_request_budget SET lease_token='',lease_until_ns=0 WHERE run_id=? AND lease_token=?", runID, token)
	return err
}

package store

import (
	"context"
	"errors"
	"time"
)

var errUnresolvedCleanup = errors.New("run has unresolved test-write cleanup obligations")
var errUnresolvedAgentJob = errors.New("run has unfinished or unknown-outcome agent jobs")
var errRunNotExpired = errors.New("run received a newer event and is no longer expired")

// RetentionResult counts runs eligible for expiry and obligations that block
// deletion. The policy is explicit and does not remove backups or storage
// remnants. Days are bounded so a typo cannot request an unbounded sweep.
type RetentionResult struct {
	Eligible int
	Blocked  int
	Purged   int
}

func retentionCutoff(now time.Time, days int) (time.Time, error) {
	if days < 1 || days > 365 {
		return time.Time{}, errors.New("retention days must be between 1 and 365")
	}
	return now.UTC().AddDate(0, 0, -days), nil
}

func (s *Store) expiredRunIDs(ctx context.Context, cutoff time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT run_id,MAX(at) FROM events GROUP BY run_id ORDER BY MAX(at),run_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id, latest string
		if err := rows.Scan(&id, &latest); err != nil {
			return nil, err
		}
		at, err := time.Parse(time.RFC3339Nano, latest)
		if err != nil {
			return nil, err
		}
		if at.Before(cutoff) {
			ids = append(ids, id)
		}
	}
	return ids, rows.Err()
}

func (s *Store) RetentionPlan(ctx context.Context, now time.Time, days int) (RetentionResult, error) {
	var result RetentionResult
	cutoff, err := retentionCutoff(now, days)
	if err != nil {
		return result, err
	}
	ids, err := s.expiredRunIDs(ctx, cutoff)
	if err != nil {
		return result, err
	}
	for _, id := range ids {
		var unresolved int
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM test_actions WHERE run_id=? AND status NOT IN (?,?)", id, TestActionPlanned, TestActionFixtureVerified).Scan(&unresolved); err != nil {
			return result, err
		}
		var active int
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM fixture_request_budget WHERE run_id=? AND lease_token<>'' AND lease_until_ns>?", id, now.UnixNano()).Scan(&active); err != nil {
			return result, err
		}
		var agentJobs int
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM agent_jobs WHERE run_id=? AND status IN ('pending','running','interrupted')", id).Scan(&agentJobs); err != nil {
			return result, err
		}
		if unresolved == 0 && active == 0 && agentJobs == 0 {
			result.Eligible++
		} else {
			result.Blocked++
		}
	}
	return result, nil
}

// PruneExpired applies the same cutoff again inside each purge transaction.
// It skips unresolved cleanup obligations and refuses runs with newer events.
func (s *Store) PruneExpired(ctx context.Context, now time.Time, days int) (RetentionResult, error) {
	var result RetentionResult
	cutoff, err := retentionCutoff(now, days)
	if err != nil {
		return result, err
	}
	ids, err := s.expiredRunIDs(ctx, cutoff)
	if err != nil {
		return result, err
	}
	for _, id := range ids {
		err := s.purgeRun(ctx, id, &cutoff)
		switch {
		case err == nil:
			result.Eligible++
			result.Purged++
		case errors.Is(err, errUnresolvedCleanup), errors.Is(err, errActiveFixtureRequest), errors.Is(err, errUnresolvedAgentJob):
			result.Blocked++
		case errors.Is(err, errRunNotExpired):
			// Another writer extended this run after selection.
		default:
			return result, err
		}
	}
	return result, nil
}

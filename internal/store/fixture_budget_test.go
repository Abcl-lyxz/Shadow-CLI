package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"shadow/internal/policy"
)

func TestFixtureRequestBudgetPersistsAndReservesCleanup(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "shadow.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := policy.FromTarget("http://fixture.test")
	if err := st.StartRun(ctx, "run-1", scope, nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < fixtureOrdinaryRequests; i++ {
		token, err := st.ReserveFixtureRequest(ctx, "run-1", false, time.Nanosecond)
		if err != nil {
			t.Fatalf("ordinary request %d: %v", i, err)
		}
		if err := st.ReleaseFixtureRequest(ctx, "run-1", token); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.ReserveFixtureRequest(ctx, "run-1", false, time.Nanosecond); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("ordinary budget reset after restart: %v", err)
	}
	for i := 0; i < fixtureCleanupRequests; i++ {
		token, err := st.ReserveFixtureRequest(ctx, "run-1", true, time.Nanosecond)
		if err != nil {
			t.Fatalf("cleanup request %d: %v", i, err)
		}
		if err := st.ReleaseFixtureRequest(ctx, "run-1", token); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.ReserveFixtureRequest(ctx, "run-1", true, time.Nanosecond); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("cleanup budget exceeded: %v", err)
	}
	if err := st.PurgeRun(ctx, "run-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ReserveFixtureRequest(ctx, "run-1", true, time.Nanosecond); err == nil {
		t.Fatal("purged run retained a request budget")
	}
}

func TestFixtureRequestLeaseAndRateSurviveRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "shadow.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := policy.FromTarget("http://fixture.test")
	if err := st.StartRun(ctx, "run-1", scope, nil); err != nil {
		t.Fatal(err)
	}
	token, err := st.ReserveFixtureRequest(ctx, "run-1", false, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	waitCtx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := st.ReserveFixtureRequest(waitCtx, "run-1", false, time.Nanosecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second request bypassed active lease: %v", err)
	}
	if err := st.ReleaseFixtureRequest(ctx, "run-1", token); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	quietCtx, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	defer stop()
	if _, err := st.ReserveFixtureRequest(quietCtx, "run-1", false, time.Hour); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("restart reset the request interval: %v", err)
	}
	if _, err := st.db.ExecContext(ctx, "DELETE FROM fixture_request_budget WHERE run_id='run-1'"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ReserveFixtureRequest(ctx, "run-1", false, time.Nanosecond); err == nil {
		t.Fatal("missing budget row was recreated")
	}
}

func TestFixtureRequestBudgetConcurrentReservationsCannotOverspend(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	scope, _ := policy.FromTarget("http://fixture.test")
	if err := st.StartRun(ctx, "run-1", scope, nil); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := 0; i < fixtureOrdinaryRequests+8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			requestCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			token, err := st.ReserveFixtureRequest(requestCtx, "run-1", false, time.Nanosecond)
			if err != nil {
				return
			}
			mu.Lock()
			success++
			mu.Unlock()
			if err := st.ReleaseFixtureRequest(ctx, "run-1", token); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if success != fixtureOrdinaryRequests {
		t.Fatalf("concurrent reservations=%d, want %d", success, fixtureOrdinaryRequests)
	}
}

func TestRetentionWaitsForActiveFixtureRequest(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	scope, _ := policy.FromTarget("http://fixture.test")
	if err := st.StartRun(ctx, "run-1", scope, nil); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	old := now.AddDate(0, 0, -10).Format(time.RFC3339Nano)
	if _, err := st.db.ExecContext(ctx, "UPDATE events SET at=? WHERE run_id=?", old, "run-1"); err != nil {
		t.Fatal(err)
	}
	token, err := st.ReserveFixtureRequest(ctx, "run-1", false, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := st.RetentionPlan(ctx, now, 7)
	if err != nil || plan != (RetentionResult{Blocked: 1}) {
		t.Fatalf("active request not in blocked plan: %+v %v", plan, err)
	}
	result, err := st.PruneExpired(ctx, now, 7)
	if err != nil || result != (RetentionResult{Blocked: 1}) {
		t.Fatalf("retention pruned an active request: %+v %v", result, err)
	}
	if err := st.ReleaseFixtureRequest(ctx, "run-1", token); err != nil {
		t.Fatal(err)
	}
	result, err = st.PruneExpired(ctx, now, 7)
	if err != nil || result.Purged != 1 {
		t.Fatalf("completed request stayed blocked: %+v %v", result, err)
	}
}

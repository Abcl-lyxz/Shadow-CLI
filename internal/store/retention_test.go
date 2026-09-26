package store

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"shadow/internal/policy"
)

func TestRetentionPrunePreservesActiveRunsAndCleanupObligations(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	st, err := Open(filepath.Join(root, "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	scope, _ := policy.FromTarget("http://fixture.test")
	decision := testWriteDecision(t)
	for _, run := range []struct {
		id    string
		rules []policy.ActionRule
	}{{"old", nil}, {"recent", nil}, {"blocked", []policy.ActionRule{decision.Rule}}} {
		if err := st.StartRun(ctx, run.id, scope, run.rules); err != nil {
			t.Fatal(err)
		}
	}
	actionID, err := st.PlanTestWrite(ctx, "blocked", decision)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MarkTestWritePossible(ctx, "blocked", actionID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	oldAt := now.AddDate(0, 0, -10).Format(time.RFC3339Nano)
	if _, err := st.db.ExecContext(ctx, "UPDATE events SET at=? WHERE run_id IN ('old','blocked')", oldAt); err != nil {
		t.Fatal(err)
	}
	if err := st.ConfigureEvidenceKey(ctx, bytes.Repeat([]byte{0x28}, 32)); err != nil {
		t.Fatal(err)
	}
	if err := st.EnableProvenance(ctx, filepath.Join(root, "ledger", "events.log"), filepath.Join(root, "custody", "head")); err != nil {
		t.Fatal(err)
	}
	plan, err := st.RetentionPlan(ctx, now, 7)
	if err != nil || plan != (RetentionResult{Eligible: 1, Blocked: 1}) {
		t.Fatalf("unexpected plan: %+v %v", plan, err)
	}
	result, err := st.PruneExpired(ctx, now, 7)
	if err != nil || result != (RetentionResult{Eligible: 1, Blocked: 1, Purged: 1}) {
		t.Fatalf("unexpected prune: %+v %v", result, err)
	}
	if err := st.AuditProvenance(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RunSnapshot(ctx, "old"); err == nil {
		t.Fatal("expired run survived prune")
	}
	for _, id := range []string{"recent", "blocked"} {
		if _, err := st.RunSnapshot(ctx, id); err != nil {
			t.Fatalf("run %s was removed: %v", id, err)
		}
	}
	if _, err := st.RetentionPlan(ctx, now, 0); err == nil {
		t.Fatal("unbounded retention days accepted")
	}
	cutoff := now.AddDate(0, 0, -7)
	if err := st.purgeRun(ctx, "recent", &cutoff); !errors.Is(err, errRunNotExpired) {
		t.Fatalf("recent run was not protected inside purge transaction: %v", err)
	}
}

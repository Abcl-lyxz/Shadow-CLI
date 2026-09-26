package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"shadow/internal/policy"
)

func TestRunSnapshotLimitsWritesAndIsImmutable(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	scope, _ := policy.FromTarget("http://fixture.test")
	decision := testWriteDecision(t)
	if err := st.StartRun(ctx, "run-1", scope, []policy.ActionRule{decision.Rule}); err != nil {
		t.Fatal(err)
	}
	if err := st.StartRun(ctx, "run-1", scope, nil); err == nil {
		t.Fatal("run snapshot was replaced")
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE run_snapshots SET actions='[]' WHERE run_id='run-1'"); err == nil {
		t.Fatal("snapshot accepted an update")
	}
	snap, err := st.RunSnapshot(ctx, "run-1")
	if err != nil || snap.Origin != scope.Origin || len(snap.Actions) != 1 {
		t.Fatalf("snapshot: %#v %v", snap, err)
	}
	if snap.Actions[0].URLSHA256 != routeHash(decision.Rule.URL) || snap.Actions[0].CleanupURLSHA256 != routeHash(decision.Rule.CleanupURL) {
		t.Fatal("snapshot did not bind exact routes")
	}
	var encoded string
	if err := st.db.QueryRowContext(ctx, "SELECT actions FROM run_snapshots WHERE run_id=?", "run-1").Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded, "token=private") || strings.Contains(encoded, "/markers") {
		t.Fatalf("raw URL leaked into snapshot: %s", encoded)
	}
	if _, err := st.PlanTestWrite(ctx, "run-1", decision); err != nil {
		t.Fatalf("snapshotted rule rejected: %v", err)
	}
	changed := decision
	changed.Rule.CleanupURL = scope.Origin + "/markers/another"
	if _, err := st.PlanTestWrite(ctx, "run-1", changed); err == nil {
		t.Fatal("changed cleanup route accepted after run start")
	}
	if err := st.Append(ctx, "legacy", "started", map[string]string{"scope": scope.Origin}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PlanTestWrite(ctx, "legacy", decision); err == nil {
		t.Fatal("legacy run gained a write permission without a snapshot")
	}
	if err := st.PurgeRun(ctx, "run-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RunSnapshot(ctx, "run-1"); err == nil {
		t.Fatal("snapshot survived run purge")
	}
}

func TestReviewTestActionRequiresCurrentStateAndSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "shadow.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := policy.FromTarget("http://fixture.test")
	decision := testWriteDecision(t)
	if err := st.StartRun(ctx, "run-1", scope, []policy.ActionRule{decision.Rule}); err != nil {
		t.Fatal(err)
	}
	id, err := st.PlanTestWrite(ctx, "run-1", decision)
	if err != nil {
		t.Fatal(err)
	}
	actions, err := st.TestActions(ctx, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ReviewTestAction(ctx, "run-1", id, actions[0].StateEventID); err == nil {
		t.Fatal("planned write was reviewed as a cleanup obligation")
	}
	if err := st.MarkTestWritePossible(ctx, "run-1", id); err != nil {
		t.Fatal(err)
	}
	actions, _ = st.TestActions(ctx, "run-1")
	stateID := actions[0].StateEventID
	if err := st.ReviewTestAction(ctx, "run-2", id, stateID); err == nil {
		t.Fatal("cross-run review accepted")
	}
	if err := st.ReviewTestAction(ctx, "run-1", id, stateID-1); err == nil {
		t.Fatal("stale review accepted")
	}
	if err := st.ReviewTestAction(ctx, "run-1", id, stateID); err != nil {
		t.Fatal(err)
	}
	if err := st.ReviewTestAction(ctx, "run-1", id, stateID); err == nil {
		t.Fatal("duplicate review accepted")
	}
	if err := st.MarkCleanupAttempted(ctx, "run-1", id); err != nil {
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
	actions, err = st.TestActions(ctx, "run-1")
	if err != nil || len(actions) != 1 {
		t.Fatalf("reopened action: %#v %v", actions, err)
	}
	if actions[0].Status != TestActionCleanupAttempted || actions[0].ReviewedStateID != stateID || actions[0].StateEventID == stateID {
		t.Fatalf("review unexpectedly closed or followed obligation: %#v", actions[0])
	}
	if err := st.ReviewTestAction(ctx, "run-1", id, stateID); err == nil {
		t.Fatal("old state review accepted after restart")
	}
	if err := st.ReviewTestAction(ctx, "run-1", id, actions[0].StateEventID); err != nil {
		t.Fatal(err)
	}
	actions, _ = st.TestActions(ctx, "run-1")
	if actions[0].ReviewedStateID != actions[0].StateEventID || actions[0].Status != TestActionCleanupAttempted {
		t.Fatalf("review changed cleanup status: %#v", actions[0])
	}
}

func TestLegacyTestActionJournalGetsReviewStateColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, at TEXT NOT NULL, kind TEXT NOT NULL, payload BLOB NOT NULL)",
		"CREATE TABLE test_actions (id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, origin TEXT NOT NULL, resource TEXT NOT NULL, method TEXT NOT NULL, url_sha256 TEXT NOT NULL, cleanup_method TEXT NOT NULL, cleanup_url_sha256 TEXT NOT NULL, status TEXT NOT NULL, planned_event_id INTEGER NOT NULL, write_event_id INTEGER, cleanup_event_id INTEGER, observation_event_id INTEGER)",
		"INSERT INTO events(run_id,at,kind,payload) VALUES('legacy','2026-01-01T00:00:00Z','started','{}')",
		"INSERT INTO test_actions(run_id,origin,resource,method,url_sha256,cleanup_method,cleanup_url_sha256,status,planned_event_id) VALUES('legacy','http://fixture.test','shadow_marker_1','POST','hash','DELETE','hash','planned',1)",
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	actions, err := st.TestActions(context.Background(), "legacy")
	if err != nil || len(actions) != 1 || actions[0].StateEventID <= actions[0].PlannedEventID {
		t.Fatalf("legacy migration: %#v %v", actions, err)
	}
	state, err := st.EventInRun(context.Background(), "legacy", actions[0].StateEventID)
	if err != nil || state.Kind != "test_action_state_migrated" {
		t.Fatalf("migration state event: %#v %v", state, err)
	}
}

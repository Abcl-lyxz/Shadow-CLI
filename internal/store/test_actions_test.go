package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"shadow/internal/policy"
)

func testWriteDecision(t *testing.T) policy.ActionDecision {
	t.Helper()
	scope, _ := policy.FromTarget("http://fixture.test")
	rule := policy.ActionRule{
		URL: scope.Origin + "/markers?token=private", Method: "POST", Effect: policy.EffectTestWrite,
		Resource: "shadow_marker_1", CleanupURL: scope.Origin + "/markers/shadow_marker_1?token=private", CleanupMethod: "DELETE",
	}
	p, err := policy.NewActionPolicy(scope, []policy.ActionRule{rule})
	if err != nil {
		t.Fatal(err)
	}
	return p.Classify(rule.Method, rule.URL)
}

func TestTestWriteJournalFailClosedAndPurge(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "shadow.db")
	st, err := OpenWithEvidenceKey(path, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { st.Close() }()
	decision := testWriteDecision(t)
	if _, err := st.PlanTestWrite(ctx, "run-1", decision); err == nil {
		t.Fatal("accepted write plan for missing run")
	}
	scope, _ := policy.FromTarget("http://fixture.test")
	if err := st.StartRun(ctx, "run-1", scope, []policy.ActionRule{decision.Rule}); err != nil {
		t.Fatal(err)
	}
	if err := st.StartRun(ctx, "run-2", scope, nil); err != nil {
		t.Fatal(err)
	}
	denied := decision
	denied.Allowed = false
	if _, err := st.PlanTestWrite(ctx, "run-1", denied); err == nil {
		t.Fatal("accepted denied write")
	}
	id, err := st.PlanTestWrite(ctx, "run-1", decision)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MarkCleanupAttempted(ctx, "run-1", id); err == nil {
		t.Fatal("cleanup attempt before write dispatch accepted")
	}
	if err := st.MarkTestWritePossible(ctx, "run-2", id); err == nil {
		t.Fatal("cross-run transition accepted")
	}
	if err := st.MarkTestWritePossible(ctx, "run-1", id); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkTestWritePossible(ctx, "run-1", id); err == nil {
		t.Fatal("duplicate write dispatch accepted")
	}
	summary, raw := responseFixture(t, "fixture")
	early, err := st.RecordObservation(ctx, "run-1", summary, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MarkCleanupAttempted(ctx, "run-1", id); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordCleanupObservation(ctx, "run-1", id, early); err == nil {
		t.Fatal("observation before cleanup attempt accepted")
	}
	old, err := st.RecordObservation(ctx, "run-2", summary, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordCleanupObservation(ctx, "run-1", id, old); err == nil {
		t.Fatal("cross-run cleanup observation accepted")
	}
	if err := st.RecordCleanupObservation(ctx, "run-1", id, 999999); err == nil {
		t.Fatal("missing cleanup observation accepted")
	}
	otherSummary := summary
	otherSummary.Origin = "http://other.test"
	u := sha256.Sum256([]byte("http://other.test/safe?token=private"))
	otherSummary.URLSHA256 = hex.EncodeToString(u[:])
	otherRaw := bytes.Replace(raw, []byte("fixture.test"), []byte("other.test"), 1)
	otherID, err := st.RecordObservation(ctx, "run-1", otherSummary, otherRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordCleanupObservation(ctx, "run-1", id, otherID); err == nil {
		t.Fatal("wrong-origin cleanup observation accepted")
	}
	if err := st.MarkCleanupFailed(ctx, "run-1", id); err != nil {
		t.Fatal(err)
	}
	if err := st.RetryCleanup(ctx, "run-1", id); err != nil {
		t.Fatal(err)
	}
	observation, err := st.RecordObservation(ctx, "run-1", summary, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordCleanupObservation(ctx, "run-1", id, observation); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkCleanupFailed(ctx, "run-1", id); err == nil {
		t.Fatal("cleanup observed action regressed")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = OpenWithEvidenceKey(path, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	actions, err := st.TestActions(ctx, "run-1")
	if err != nil || len(actions) != 1 || actions[0].Status != TestActionCleanupObserved || actions[0].ObservationEventID != observation {
		t.Fatalf("journal after reopen: %#v %v", actions, err)
	}
	events, err := st.Events(ctx, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if strings.Contains(string(event.Payload), "token=private") || strings.Contains(string(event.Payload), "/markers") {
			t.Fatalf("journal leaked route in event %d", event.ID)
		}
	}
	if err := st.PurgeRun(ctx, "run-1"); err != nil {
		t.Fatal(err)
	}
	actions, err = st.TestActions(ctx, "run-1")
	if err != nil || len(actions) != 0 {
		t.Fatalf("journal survived purge: %#v %v", actions, err)
	}
	if other, err := st.Events(ctx, "run-2"); err != nil || len(other) == 0 {
		t.Fatalf("other run removed: %#v %v", other, err)
	}
}

func TestInterruptedCleanupObligationsSurviveRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "shadow.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	decision := testWriteDecision(t)
	scope, _ := policy.FromTarget("http://fixture.test")
	if err := st.StartRun(ctx, "run-1", scope, []policy.ActionRule{decision.Rule}); err != nil {
		t.Fatal(err)
	}
	beforeDispatch, err := st.PlanTestWrite(ctx, "run-1", decision)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MarkTestWritePossible(ctx, "run-1", beforeDispatch); err != nil {
		t.Fatal(err)
	}
	duringCleanup, err := st.PlanTestWrite(ctx, "run-1", decision)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MarkTestWritePossible(ctx, "run-1", duringCleanup); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkCleanupAttempted(ctx, "run-1", duringCleanup); err != nil {
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
	actions, err := st.TestActions(ctx, "run-1")
	if err != nil || len(actions) != 2 {
		t.Fatalf("recovered obligations: %#v %v", actions, err)
	}
	if actions[0].ID != beforeDispatch || actions[0].Status != TestActionWritePossible || actions[0].WriteEventID == 0 || actions[0].CleanupEventID != 0 {
		t.Fatalf("lost uncertain write: %#v", actions[0])
	}
	if actions[1].ID != duringCleanup || actions[1].Status != TestActionCleanupAttempted || actions[1].CleanupEventID == 0 || actions[1].ObservationEventID != 0 {
		t.Fatalf("lost cleanup attempt: %#v", actions[1])
	}
	if err := st.MarkTestWritePossible(ctx, "run-1", beforeDispatch); err == nil {
		t.Fatal("replayed write after restart")
	}
	if err := st.MarkCleanupAttempted(ctx, "run-1", duringCleanup); err == nil {
		t.Fatal("replayed cleanup after restart")
	}
}

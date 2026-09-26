package store

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

func TestEventPersistsAcrossOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shadow.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Append(context.Background(), "run-1", "observation", map[string]string{"detail": "example"}); err != nil {
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
	events, err := st.Events(context.Background(), "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != "observation" {
		t.Fatalf("events = %#v", events)
	}
}

func TestPurgeRunRemovesOnlySelectedRun(t *testing.T) {
	ctx := context.Background()
	st, err := OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	summary, raw := responseFixture(t, "evidence")
	first, err := st.RecordObservation(ctx, "run-1", summary, raw)
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.RecordObservation(ctx, "run-2", summary, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Remember(ctx, summary.Origin, "run-1", "agent", "topic", "summary", first); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateFinding(ctx, "run-1", "Observed response", summary.Origin, ClaimResponseObservation, first); err != nil {
		t.Fatal(err)
	}
	if err := st.PurgeRun(ctx, "run-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RawEvidence(ctx, "run-1", first); err == nil {
		t.Fatal("purged evidence still accessible")
	}
	if events, err := st.Events(ctx, "run-1"); err != nil || len(events) != 0 {
		t.Fatalf("purged events: %v %#v", err, events)
	}
	if findings, err := st.Findings(ctx, "run-1"); err != nil || len(findings) != 0 {
		t.Fatalf("purged findings: %v %#v", err, findings)
	}
	if notes, err := st.Recall(ctx, summary.Origin, 10); err != nil || len(notes) != 0 {
		t.Fatalf("purged memories: %v %#v", err, notes)
	}
	if _, err := st.RawEvidence(ctx, "run-2", second); err != nil {
		t.Fatalf("other run evidence lost: %v", err)
	}
	if err := st.PurgeRun(ctx, "run-1"); err == nil {
		t.Fatal("missing run purge succeeded")
	}
}

func TestMemoryIsScopeBoundAndHasEvidence(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	eventID, err := st.AppendWithID(context.Background(), "run-1", "observation", map[string]string{"text": "header observed"})
	if err != nil {
		t.Fatal(err)
	}
	if event, err := st.EventInRun(context.Background(), "run-1", eventID); err != nil || event.ID != eventID {
		t.Fatalf("same-run event lookup failed: %#v, %v", event, err)
	}
	if _, err := st.EventInRun(context.Background(), "other-run", eventID); err == nil {
		t.Fatal("cross-run event lookup succeeded")
	}
	if err := st.Remember(context.Background(), "https://a.example", "run-1", "recon", "headers", "HSTS absent", eventID); err != nil {
		t.Fatal(err)
	}
	if err := st.Remember(context.Background(), "https://a.example", "run-1", "recon", "invalid", "no source", 99999); err == nil {
		t.Fatal("memory accepted missing source event")
	}
	if err := st.Remember(context.Background(), "https://a.example", "other-run", "recon", "invalid", "wrong run", eventID); err == nil {
		t.Fatal("memory accepted another run's event")
	}
	for scope, want := range map[string]int{"https://a.example": 1, "https://b.example": 0} {
		memories, err := st.Recall(context.Background(), scope, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(memories) != want {
			t.Fatalf("scope %s returned %d memories", scope, len(memories))
		}
	}
}

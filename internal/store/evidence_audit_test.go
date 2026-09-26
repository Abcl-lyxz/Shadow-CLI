package store

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestAuditEvidenceChecksAllPairsWithoutReturningRawData(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x42}, 32)
	st, err := OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ids := make([]int64, 3)
	for i, body := range []string{"first private@example.com", "second private@example.com", "third private@example.com"} {
		summary, raw := responseFixture(t, body)
		ids[i], err = st.RecordObservation(ctx, "run-1", summary, raw)
		if err != nil {
			t.Fatal(err)
		}
	}
	check := func(key []byte, want EvidenceAudit) {
		t.Helper()
		got, err := st.AuditEvidence(ctx, key)
		if err != nil || got != want {
			t.Fatalf("audit: got %+v, %v; want %+v", got, err, want)
		}
		encoded, err := json.Marshal(got)
		if err != nil || bytes.Contains(encoded, []byte("private")) || bytes.Contains(encoded, []byte("fixture")) {
			t.Fatalf("audit exposed raw data: %s, %v", encoded, err)
		}
	}
	check(key, EvidenceAudit{Total: 3, Valid: 3})
	check(bytes.Repeat([]byte{0x43}, 32), EvidenceAudit{Total: 3, Invalid: 3})
	if _, err := st.AuditEvidence(ctx, nil); err == nil {
		t.Fatal("encrypted records audited without a key")
	}
	if _, err := st.db.Exec("UPDATE evidence SET ciphertext=? WHERE event_id=?", []byte("tampered"), ids[1]); err != nil {
		t.Fatal(err)
	}
	check(key, EvidenceAudit{Total: 3, Valid: 2, Invalid: 1})
	if _, err := st.db.Exec("UPDATE events SET payload=? WHERE id=?", []byte(`{"status":201}`), ids[2]); err != nil {
		t.Fatal(err)
	}
	check(key, EvidenceAudit{Total: 3, Valid: 1, Invalid: 2})
	if _, err := st.db.Exec("DELETE FROM evidence WHERE event_id=?", ids[0]); err != nil {
		t.Fatal(err)
	}
	check(key, EvidenceAudit{Total: 3, Invalid: 3})
}

func TestAuditEvidenceFindsDetachedOrMisclassifiedRecords(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x42}, 32)
	st, err := OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	summary, raw := responseFixture(t, "body")
	id, err := st.RecordObservation(ctx, "run-1", summary, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("UPDATE events SET kind='other' WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	got, err := st.AuditEvidence(ctx, key)
	if err != nil || got != (EvidenceAudit{Total: 1, Invalid: 1}) {
		t.Fatalf("misclassified record: %+v, %v", got, err)
	}
	if _, err := st.db.Exec("UPDATE events SET kind='observation' WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("UPDATE evidence SET run_id='run-2' WHERE event_id=?", id); err != nil {
		t.Fatal(err)
	}
	got, err = st.AuditEvidence(ctx, key)
	if err != nil || got != (EvidenceAudit{Total: 2, Invalid: 2}) {
		t.Fatalf("run mismatch: %+v, %v", got, err)
	}
}

func TestAuditEvidenceReportsOrphanObservationWithoutKey(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got, err := st.AuditEvidence(ctx, nil)
	if err != nil || got != (EvidenceAudit{}) {
		t.Fatalf("empty audit: %+v, %v", got, err)
	}
	if err := st.Append(ctx, "run-1", "observation", map[string]string{"route": "secret"}); err != nil {
		t.Fatal(err)
	}
	got, err = st.AuditEvidence(ctx, nil)
	if err != nil || got != (EvidenceAudit{Total: 1, Invalid: 1}) {
		t.Fatalf("orphan observation: %+v, %v", got, err)
	}
}

func TestMalformedEvidenceNonceFailsWithoutPanic(t *testing.T) {
	ctx := context.Background()
	key := bytes.Repeat([]byte{0x42}, 32)
	st, err := OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	summary, raw := responseFixture(t, "body")
	id, err := st.RecordObservation(ctx, "run-1", summary, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec("UPDATE evidence SET nonce=? WHERE event_id=?", []byte("short"), id); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RawEvidence(ctx, "run-1", id); err == nil {
		t.Fatal("malformed nonce was accepted")
	}
	got, err := st.AuditEvidence(ctx, key)
	if err != nil || got != (EvidenceAudit{Total: 1, Invalid: 1}) {
		t.Fatalf("malformed nonce audit: %+v, %v", got, err)
	}
}

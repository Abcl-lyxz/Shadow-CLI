package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func provenanceFixture(t *testing.T) (*Store, string, string, string, []byte) {
	t.Helper()
	root := t.TempDir()
	database := filepath.Join(root, "data", "shadow.db")
	key := bytes.Repeat([]byte{0x35}, 32)
	st, err := OpenWithEvidenceKey(database, key)
	if err != nil {
		t.Fatal(err)
	}
	ledger, head := DefaultProvenancePaths(database)
	if err := st.EnableProvenance(context.Background(), ledger, head); err != nil {
		st.Close()
		t.Fatal(err)
	}
	return st, database, ledger, head, key
}

func TestProvenanceDetectsEventAndEvidenceTamper(t *testing.T) {
	ctx := context.Background()
	st, database, ledger, head, key := provenanceFixture(t)
	url := "http://fixture.test/private"
	response := RawHTTP{RequestURL: url, Method: http.MethodGet, Status: 200, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: []byte("sensitive response")}
	raw, _ := json.Marshal(response)
	u := sha256.Sum256([]byte(url))
	b := sha256.Sum256(response.Body)
	id, err := st.RecordObservation(ctx, "run-1", EvidenceSummary{Origin: "http://fixture.test", URLSHA256: hex.EncodeToString(u[:]), Status: 200, ContentType: "text/plain", Bytes: len(response.Body), SHA256: hex.EncodeToString(b[:])}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Append(ctx, "run-1", "note", map[string]string{"value": "safe"}); err != nil {
		t.Fatal(err)
	}
	if err := st.AuditProvenance(ctx); err != nil {
		t.Fatal(err)
	}
	ledgerData, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ledgerData, response.Body) || bytes.Contains(ledgerData, []byte(url)) {
		t.Fatal("provenance ledger disclosed raw evidence")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = OpenWithEvidenceKey(database, key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.EnableProvenance(ctx, ledger, head); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "DELETE FROM evidence WHERE event_id=?", id); err != nil {
		t.Fatal(err)
	}
	if err := st.AuditProvenance(ctx); err == nil {
		t.Fatal("coordinated evidence deletion was accepted")
	}
	if err := st.Append(ctx, "run-1", "note", nil); err == nil {
		t.Fatal("write after provenance mismatch was accepted")
	}
	if _, err := st.db.ExecContext(ctx, "DELETE FROM events WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	if err := st.AuditProvenance(ctx); err == nil {
		t.Fatal("coordinated event and evidence deletion was accepted")
	}
	if _, err := st.VerifiedSnapshotBytes(ctx, 1<<20); err == nil {
		t.Fatal("backup snapshot accepted a provenance mismatch")
	}
}

func TestProvenanceDetectsRollbackAndLedgerTruncation(t *testing.T) {
	ctx := context.Background()
	st, database, ledger, head, key := provenanceFixture(t)
	if err := st.Append(ctx, "run-1", "first", nil); err != nil {
		t.Fatal(err)
	}
	older, err := st.SnapshotBytes(ctx, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Append(ctx, "run-1", "second", nil); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(database, older, 0600); err != nil {
		t.Fatal(err)
	}
	st, err = OpenWithEvidenceKey(database, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.EnableProvenance(ctx, ledger, head); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("database rollback was accepted: %v", err)
	}
	st.Close()
	// A restored image in a fresh location may start a new, explicit chain.
	fresh := filepath.Join(t.TempDir(), "data", "restored.db")
	if err := os.MkdirAll(filepath.Dir(fresh), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fresh, older, 0600); err != nil {
		t.Fatal(err)
	}
	recovered, err := OpenWithEvidenceKey(fresh, key)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	freshLedger, freshHead := DefaultProvenancePaths(fresh)
	if err := recovered.EnableProvenance(ctx, freshLedger, freshHead); err != nil {
		t.Fatalf("fresh recovery enrollment failed: %v", err)
	}
	ledgerData, err := os.ReadFile(freshLedger)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(freshLedger, ledgerData[:len(ledgerData)-1], 0600); err != nil {
		t.Fatal(err)
	}
	if err := recovered.AuditProvenance(ctx); err == nil {
		t.Fatal("truncated ledger was accepted")
	}
}

func TestProvenanceRecordsAuthorizedPurge(t *testing.T) {
	ctx := context.Background()
	st, _, ledger, head, _ := provenanceFixture(t)
	defer st.Close()
	for _, run := range []string{"expired", "current"} {
		if err := st.Append(ctx, run, "note", nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.PurgeRun(ctx, "expired"); err != nil {
		t.Fatal(err)
	}
	if err := st.AuditProvenance(ctx); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(entries, []byte(`"reason":"purge_run"`)) {
		t.Fatal("authorized purge was not recorded")
	}
	if err := os.Remove(head); err != nil {
		t.Fatal(err)
	}
	if err := st.AuditProvenance(ctx); err == nil {
		t.Fatal("missing independent head was accepted")
	}
}

func TestProvenanceFailsClosedWhenLedgerPrecedesRolledBackTransaction(t *testing.T) {
	ctx := context.Background()
	st, database, ledger, head, key := provenanceFixture(t)
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO events(run_id,at,kind,payload) VALUES('run','2026-01-01T00:00:00Z','note','{}')"); err != nil {
		t.Fatal(err)
	}
	state, err := activeStateDigestTx(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.provenance.appendState(state, "interrupted_event"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	st.Close()
	reopened, err := OpenWithEvidenceKey(database, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.EnableProvenance(ctx, ledger, head); err == nil {
		t.Fatal("interrupted commit silently advanced the chain")
	}
}

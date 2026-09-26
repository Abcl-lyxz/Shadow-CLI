package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
)

func responseFixture(t *testing.T, body string) (EvidenceSummary, []byte) {
	t.Helper()
	url := "http://fixture.test/safe?token=private"
	raw, err := json.Marshal(RawHTTP{RequestURL: url, Method: http.MethodGet, Status: 200, Header: http.Header{"Set-Cookie": []string{"session=private"}, "Content-Type": []string{"text/plain"}}, Body: []byte(body)})
	if err != nil {
		t.Fatal(err)
	}
	u := sha256.Sum256([]byte(url))
	b := sha256.Sum256([]byte(body))
	return EvidenceSummary{Origin: "http://fixture.test", URLSHA256: hex.EncodeToString(u[:]), Status: 200, ContentType: "text/plain", Bytes: len(body), SHA256: hex.EncodeToString(b[:])}, raw
}

func TestEncryptedEvidenceIsRunBoundAndDurable(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "shadow.db")
	key := bytes.Repeat([]byte{0x42}, 32)
	st, err := OpenWithEvidenceKey(path, key)
	if err != nil {
		t.Fatal(err)
	}
	summary, raw := responseFixture(t, "private@example.com")
	if _, err := st.RecordObservation(ctx, "run-1", EvidenceSummary{}, raw); err == nil {
		t.Fatal("invalid summary accepted")
	}
	id, err := st.RecordObservation(ctx, "run-1", summary, raw)
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext []byte
	if err := st.db.QueryRow("SELECT ciphertext FROM evidence WHERE event_id=?", id).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{[]byte("private@example.com"), []byte("session=private"), []byte("token=private")} {
		if bytes.Contains(ciphertext, secret) {
			t.Fatalf("ciphertext disclosed %q", secret)
		}
	}
	events, err := st.Events(ctx, "run-1")
	if err != nil || len(events) != 1 || bytes.Contains(events[0].Payload, []byte("private")) {
		t.Fatalf("event log disclosed raw data: %v %#v", err, events)
	}
	if _, err := st.RawEvidence(ctx, "run-2", id); err == nil {
		t.Fatal("cross-run evidence read succeeded")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = OpenWithEvidenceKey(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got, err := st.RawEvidence(ctx, "run-1", id)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("evidence did not survive reopen: %v", err)
	}
	if wrong, err := OpenWithEvidenceKey(path, bytes.Repeat([]byte{0x43}, 32)); err == nil {
		wrong.Close()
		t.Fatal("wrong key opened existing evidence")
	}
	if _, err := st.db.Exec("UPDATE evidence SET ciphertext=? WHERE event_id=?", []byte("tampered"), id); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RawEvidence(ctx, "run-1", id); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
}

func TestFindingRequiresSourceAndSafeLaterReproduction(t *testing.T) {
	ctx := context.Background()
	st, err := OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	summary, raw := responseFixture(t, "reproducible response")
	source, err := st.RecordObservation(ctx, "run-1", summary, raw)
	if err != nil {
		t.Fatal(err)
	}
	earlyRepeat, err := st.RecordObservation(ctx, "run-1", summary, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateFinding(ctx, "run-2", "Response", summary.Origin, ClaimResponseObservation, source); err == nil {
		t.Fatal("cross-run source accepted")
	}
	spoofed, err := st.AppendWithID(ctx, "run-1", "observation", summary)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateFinding(ctx, "run-1", "Response", summary.Origin, ClaimResponseObservation, spoofed); err == nil {
		t.Fatal("source without raw evidence accepted")
	}
	securityID, err := st.CreateFinding(ctx, "run-1", "Possible issue", summary.Origin, ClaimSecurityHypothesis, source)
	if err != nil {
		t.Fatal(err)
	}
	responseID, err := st.CreateFinding(ctx, "run-1", "Response", summary.Origin, ClaimResponseObservation, source)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.VerifyResponseFinding(ctx, "run-1", responseID, source); err == nil {
		t.Fatal("source reused as independent reproduction")
	}
	if err := st.VerifyResponseFinding(ctx, "run-1", responseID, earlyRepeat); err == nil {
		t.Fatal("observation predating finding accepted as reproduction")
	}
	other, err := st.RecordObservation(ctx, "run-2", summary, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.VerifyResponseFinding(ctx, "run-1", responseID, other); err == nil {
		t.Fatal("cross-run reproduction accepted")
	}
	changed, changedRaw := responseFixture(t, "different response")
	changedID, err := st.RecordObservation(ctx, "run-1", changed, changedRaw)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.VerifyResponseFinding(ctx, "run-1", responseID, changedID); err == nil {
		t.Fatal("different response accepted")
	}
	repeat, err := st.RecordObservation(ctx, "run-1", summary, raw)
	if err != nil {
		t.Fatal(err)
	}
	forged := summary
	forged.SHA256 = changed.SHA256
	forgedPayload, _ := json.Marshal(forged)
	if _, err := st.db.Exec("UPDATE events SET payload=? WHERE id=?", forgedPayload, repeat); err != nil {
		t.Fatal(err)
	}
	if err := st.VerifyResponseFinding(ctx, "run-1", responseID, repeat); err == nil {
		t.Fatal("tampered event summary was accepted")
	}
	truePayload, _ := json.Marshal(summary)
	if _, err := st.db.Exec("UPDATE events SET payload=? WHERE id=?", truePayload, repeat); err != nil {
		t.Fatal(err)
	}
	if err := st.VerifyResponseFinding(ctx, "run-1", securityID, repeat); err == nil {
		t.Fatal("security hypothesis upgraded by response match")
	}
	if err := st.VerifyResponseFinding(ctx, "run-1", responseID, repeat); err != nil {
		t.Fatal(err)
	}
	findings, err := st.Findings(ctx, "run-1")
	if err != nil || len(findings) != 2 || findings[0].Status != "hypothesis" || findings[1].Status != "verified" || findings[1].ReproductionEventID != repeat {
		t.Fatalf("finding states: %v %#v", err, findings)
	}
}

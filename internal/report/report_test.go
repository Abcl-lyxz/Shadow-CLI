package report

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"shadow/internal/store"
)

func evidence(t *testing.T, st *store.Store, run, body string) int64 {
	t.Helper()
	u := "http://fixture.test/safe?token=private"
	h := sha256.Sum256([]byte(u))
	b := sha256.Sum256([]byte(body))
	raw, _ := json.Marshal(store.RawHTTP{RequestURL: u, Method: http.MethodGet, Status: 200, Body: []byte(body)})
	id, err := st.RecordObservation(context.Background(), run, store.EvidenceSummary{Origin: "http://fixture.test", URLSHA256: hex.EncodeToString(h[:]), Status: 200, Bytes: len(body), SHA256: hex.EncodeToString(b[:])}, raw)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestReviewedMetadataExportsAndEvidenceGate(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	source := evidence(t, st, "run-1", "private@example.com")
	id, err := st.CreateFinding(ctx, "run-1", "customer-code-48217", "http://fixture.test", store.ClaimSecurityHypothesis, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Prepare(ctx, st, "run-1"); err == nil {
		t.Fatal("unreviewed finding exported")
	}
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"
	if _, err := st.ReviewFinding(ctx, "run-1", id, "response_reproduced", "high", 0, vector); err == nil {
		t.Fatal("security hypothesis acquired verified PoC")
	}
	r, err := st.ReviewFinding(ctx, "run-1", id, "not_attempted", "medium", 0, vector)
	if err != nil {
		t.Fatal(err)
	}
	if r.CVSSScore == nil || *r.CVSSScore != 8.7 {
		t.Fatalf("FIRST reference vector score: %#v", r.CVSSScore)
	}
	doc, digest, err := Prepare(ctx, st, "run-1")
	if err != nil || len(digest) != 64 || len(doc.Findings) != 1 || doc.Findings[0].Status != "hypothesis" {
		t.Fatalf("prepare: %v %#v %s", err, doc, digest)
	}
	for _, format := range []string{"html", "pdf", "json", "sarif"} {
		out, err := Render(doc, format)
		if err != nil || len(out) == 0 {
			t.Fatalf("%s render: %v", format, err)
		}
		for _, secret := range []string{"private@example.com", "token=private", "customer-code-48217"} {
			if bytes.Contains(out, []byte(secret)) {
				t.Fatalf("%s leaked %q", format, secret)
			}
		}
		if format == "pdf" && (!bytes.HasPrefix(out, []byte("%PDF-1.4")) || !bytes.Contains(out, []byte("startxref"))) {
			t.Fatal("malformed PDF skeleton")
		}
		if format == "sarif" {
			var sarif struct {
				Version string            `json:"version"`
				Runs    []json.RawMessage `json:"runs"`
			}
			if err := json.Unmarshal(out, &sarif); err != nil || sarif.Version != "2.1.0" || len(sarif.Runs) != 1 {
				t.Fatalf("SARIF: %v", err)
			}
		}
	}
	if _, err := st.ReviewFinding(ctx, "run-1", id, "blocked", "low", 0, vector); err != nil {
		t.Fatal(err)
	}
	_, next, err := Prepare(ctx, st, "run-1")
	if err != nil || next == digest {
		t.Fatal("changed review did not change export digest")
	}
	if strings.Contains(doc.Notice, "verified vulnerability") {
		t.Fatal("unsafe report notice")
	}
}

func TestDuplicateMustBeEarlierCanonicalSameRun(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	source := evidence(t, st, "run-1", "safe")
	first, _ := st.CreateFinding(ctx, "run-1", "first", "http://fixture.test", store.ClaimSecurityHypothesis, source)
	second, _ := st.CreateFinding(ctx, "run-1", "second", "http://fixture.test", store.ClaimSecurityHypothesis, source)
	third, _ := st.CreateFinding(ctx, "run-1", "third", "http://fixture.test", store.ClaimSecurityHypothesis, source)
	if _, err := st.ReviewFinding(ctx, "run-1", second, "not_attempted", "low", first, ""); err != nil {
		t.Fatal(err)
	}
	for _, target := range []int64{second, third} {
		if _, err := st.ReviewFinding(ctx, "run-1", third, "not_attempted", "low", target, ""); err == nil {
			t.Fatalf("accepted duplicate target %d", target)
		}
	}
	other := evidence(t, st, "run-2", "safe")
	foreign, _ := st.CreateFinding(ctx, "run-2", "foreign", "http://fixture.test", store.ClaimSecurityHypothesis, other)
	if _, err := st.ReviewFinding(ctx, "run-2", foreign, "not_attempted", "low", first, ""); err == nil {
		t.Fatal("cross-run duplicate accepted")
	}
	if _, err := st.ReviewFinding(ctx, "run-1", first, "not_attempted", "low", 0, "CVSS:4.0/AV:F"); err == nil {
		t.Fatal("invalid CVSS accepted")
	}
}

func TestResponseReproductionRequiresFreshReviewForExport(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	source := evidence(t, st, "run-1", "same")
	id, err := st.CreateFinding(ctx, "run-1", "response", "http://fixture.test", store.ClaimResponseObservation, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ReviewFinding(ctx, "run-1", id, "not_attempted", "low", 0, ""); err != nil {
		t.Fatal(err)
	}
	repeat := evidence(t, st, "run-1", "same")
	if err := st.VerifyResponseFinding(ctx, "run-1", id, repeat); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Prepare(ctx, st, "run-1"); err == nil {
		t.Fatal("stale review exported after verification")
	}
	if _, err := st.ReviewFinding(ctx, "run-1", id, "response_reproduced", "high", 0, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Prepare(ctx, st, "run-1"); err != nil {
		t.Fatal(err)
	}
}

func TestOperatorNarrativeRequiresCompleteRationaleAndSafeText(t *testing.T) {
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"
	score := 8.7
	doc := Document{Schema: "shadow-report-v1", RunID: "run-1", Findings: []Entry{{ID: 1, ClaimType: store.ClaimSecurityHypothesis, Status: "hypothesis", CVSSVector: vector, CVSSScore: &score}}}
	rationale := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(vector, "CVSS:4.0/"), "/") {
		key, _, _ := strings.Cut(part, ":")
		rationale[key] = "Operator explained metric"
	}
	d := Detail{FindingID: 1, Title: "<script>alert(1)</script> Access check", AssetLabel: "fixture application", CWE: "CWE-284", Observed: "A response was saved", Expected: "Access is restricted", Preconditions: "Signed in as a test user", Impact: "Impact has not been demonstrated", ValidationPlan: "Ask owner for a disposable fixture", Remediation: "Review access control", CVSSRationale: rationale, BusinessPriority: "unassigned"}
	input, _ := json.Marshal([]Detail{d})
	parsed, err := ParseDetails(input)
	if err != nil {
		t.Fatal(err)
	}
	full, digest, err := AttachDetails(doc, parsed)
	if err != nil || len(digest) != 64 {
		t.Fatalf("attach: %v", err)
	}
	for _, format := range []string{"html", "pdf", "json", "sarif"} {
		out, err := Render(full, format)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if format == "html" && (bytes.Contains(out, []byte("<script>")) || !bytes.Contains(out, []byte("&lt;script&gt;"))) {
			t.Fatal("HTML did not escape operator text")
		}
		if !bytes.Contains(out, []byte("Access check")) {
			t.Fatalf("%s omitted reviewed narrative", format)
		}
	}
	d.CVSSRationale = map[string]string{"AV": "only one metric"}
	if _, _, err := AttachDetails(doc, []Detail{d}); err == nil {
		t.Fatal("incomplete CVSS rationale accepted")
	}
	d.CVSSRationale = rationale
	d.Observed = "private@example.com"
	if _, _, err := AttachDetails(doc, []Detail{d}); err == nil {
		t.Fatal("sensitive prose accepted")
	}
	if _, err := ParseDetails([]byte(`[ {"finding_id":1,"unexpected":"value"} ]`)); err == nil {
		t.Fatal("unknown detail key accepted")
	}
	d.Observed = "A response was saved"
	d.Title = "ชื่อภาษาไทย"
	unicodeDoc, _, err := AttachDetails(doc, []Detail{d})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Render(unicodeDoc, "pdf"); err == nil {
		t.Fatal("Unicode silently degraded in PDF")
	}
}

package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	keyring "github.com/zalando/go-keyring"
	_ "modernc.org/sqlite"
	"shadow/internal/config"
	"shadow/internal/policy"
	"shadow/internal/report"
	"shadow/internal/store"
)

func TestDataAuditEvidenceUsesKeyringAndReportsCountsOnly(t *testing.T) {
	keyring.MockInit()
	key, err := config.EvidenceKey(true)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "shadow.db")
	st, err := store.OpenWithEvidenceKey(path, key)
	if err != nil {
		t.Fatal(err)
	}
	requestURL := "http://fixture.test/safe?token=private"
	urlHash := sha256.Sum256([]byte(requestURL))
	for _, body := range []string{"first private@example.com", "second private@example.com"} {
		bodyHash := sha256.Sum256([]byte(body))
		raw, err := json.Marshal(store.RawHTTP{RequestURL: requestURL, Method: http.MethodGet, Status: 200, Header: http.Header{"Content-Type": []string{"text/plain"}, "Set-Cookie": []string{"session=private"}}, Body: []byte(body)})
		if err != nil {
			t.Fatal(err)
		}
		summary := store.EvidenceSummary{Origin: "http://fixture.test", URLSHA256: hex.EncodeToString(urlHash[:]), Status: 200, ContentType: "text/plain", Bytes: len(body), SHA256: hex.EncodeToString(bodyHash[:])}
		if _, err := st.RecordObservation(context.Background(), "run-1", summary, raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	output := captureDataCommand(t, path, []string{"audit-evidence"})
	if !strings.Contains(output, "2 pairs, 2 valid, 0 invalid") {
		t.Fatalf("clean audit: %s", output)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE evidence SET ciphertext=? WHERE event_id=(SELECT MIN(event_id) FROM evidence)", []byte("tampered")); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = w
	commandErr := dataCommandAt(path, []string{"audit-evidence"})
	os.Stdout = previous
	w.Close()
	outputBytes, readErr := io.ReadAll(r)
	r.Close()
	if readErr != nil || commandErr == nil {
		t.Fatalf("tampered audit: %v, %v", readErr, commandErr)
	}
	output += string(outputBytes) + commandErr.Error()
	if !strings.Contains(string(outputBytes), "2 pairs, 1 valid, 1 invalid") {
		t.Fatalf("tampered audit counts: %s", outputBytes)
	}
	for _, secret := range []string{"token=private", "session=private", "private@example.com", "/safe"} {
		if strings.Contains(output, secret) {
			t.Fatalf("audit disclosed raw data: %s", output)
		}
	}
}

func TestIsolatedSavedObservationReviewAndReportWithoutNetwork(t *testing.T) {
	keyring.MockInit()
	key, err := config.EvidenceKey(true)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "shadow.db")
	st, err := store.OpenWithEvidenceKey(path, key)
	if err != nil {
		t.Fatal(err)
	}
	runID := "0123456789abcdef01234567"
	u := "https://fixture.example/"
	body := "saved response"
	uh := sha256.Sum256([]byte(u))
	bh := sha256.Sum256([]byte(body))
	raw, _ := json.Marshal(store.RawHTTP{RequestURL: u, Method: http.MethodGet, Status: 200, Body: []byte(body)})
	eventID, err := st.RecordObservation(context.Background(), runID, store.EvidenceSummary{Origin: "https://fixture.example", URLSHA256: hex.EncodeToString(uh[:]), Status: 200, Bytes: len(body), SHA256: hex.EncodeToString(bh[:])}, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"data", "create-observation", runID, strconv.FormatInt(eventID, 10), "--data-dir", dir}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"data", "create-observation", runID, strconv.FormatInt(eventID, 10), "--data-dir", dir}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"data", "review-finding", runID, "1", "--poc", "not_attempted", "--confidence", "low", "--data-dir", dir}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"data", "findings", runID, "--data-dir", dir}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"report", "preview", runID, "--data-dir", dir}); err != nil {
		t.Fatal(err)
	}
	st, err = store.OpenWithEvidenceKey(path, key)
	if err != nil {
		t.Fatal(err)
	}
	doc, digest, err := report.Prepare(context.Background(), st, runID)
	st.Close()
	if err != nil || len(doc.Findings) != 1 {
		t.Fatalf("prepared isolated report: %v %#v", err, doc)
	}
	out := filepath.Join(t.TempDir(), "report.json")
	if err := run([]string{"report", "export", runID, "--format", "json", "--confirm", digest, "--out", out, "--data-dir", dir}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), body) || !strings.Contains(string(b), `"response_observation"`) {
		t.Fatalf("isolated report content: %s", b)
	}
	if err := run([]string{"report", "export", runID, "--format", "json", "--confirm", digest, "--out", out, "--data-dir", dir}); err == nil {
		t.Fatal("existing report overwritten")
	}
}

func TestPurgeRunRequiresMatchingConfirmation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shadow.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Append(context.Background(), "run-1", "started", map[string]string{"scope": "fixture"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"purge-run", "run-1"}, {"purge-run", "run-1", "--confirm", "run-2"}} {
		if err := dataCommandAt(path, args); err == nil {
			t.Fatalf("unsafe command accepted: %v", args)
		}
	}
	st, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	events, err := st.Events(context.Background(), "run-1")
	st.Close()
	if err != nil || len(events) != 1 {
		t.Fatalf("rejected command changed run: %v %#v", err, events)
	}
	if err := dataCommandAt(path, []string{"purge-run", "run-1", "--confirm", "run-1"}); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	events, err = st.Events(context.Background(), "run-1")
	if err != nil || len(events) != 0 {
		t.Fatalf("confirmed command did not purge run: %v %#v", err, events)
	}
}

func TestDataTestActionsShowsPendingObligationWithoutRawRoutes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shadow.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	scope, _ := policy.FromTarget("http://fixture.test")
	rule := policy.ActionRule{URL: scope.Origin + "/markers?token=private", Method: "POST", Effect: policy.EffectTestWrite, Resource: "shadow_marker_1", CleanupURL: scope.Origin + "/markers/shadow_marker_1?token=private", CleanupMethod: "DELETE"}
	if err := st.StartRun(ctx, "run-1", scope, []policy.ActionRule{rule}); err != nil {
		t.Fatal(err)
	}
	p, err := policy.NewActionPolicy(scope, []policy.ActionRule{rule})
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.PlanTestWrite(ctx, "run-1", p.Classify(rule.Method, rule.URL))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MarkTestWritePossible(ctx, "run-1", id); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	previous := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = previous }()
	commandErr := dataCommandAt(path, []string{"test-actions", "run-1"})
	w.Close()
	output, readErr := io.ReadAll(r)
	if commandErr != nil || readErr != nil {
		t.Fatalf("list test actions: %v %v", commandErr, readErr)
	}
	if !strings.Contains(string(output), store.TestActionWritePossible) || !strings.Contains(string(output), "shadow_marker_1") {
		t.Fatalf("pending obligation not shown: %s", output)
	}
	for _, secret := range []string{"token=private", "/markers"} {
		if strings.Contains(string(output), secret) {
			t.Fatalf("raw route leaked: %s", output)
		}
	}
	if err := dataCommandAt(path, []string{"purge-run", "run-1", "--confirm", "run-1"}); err == nil {
		t.Fatal("CLI purged an unresolved cleanup obligation")
	}
	st, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	actions, err := st.TestActions(ctx, "run-1")
	if err != nil || len(actions) != 1 || actions[0].Status != store.TestActionWritePossible {
		t.Fatalf("CLI purge lost cleanup journal: %#v %v", actions, err)
	}
}

func TestDataReviewAcknowledgesOnlyObservedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shadow.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	scope, _ := policy.FromTarget("http://fixture.test")
	rule := policy.ActionRule{URL: scope.Origin + "/markers?token=private", Method: "POST", Effect: policy.EffectTestWrite, Resource: "shadow_marker_1", CleanupURL: scope.Origin + "/markers/shadow_marker_1?token=private", CleanupMethod: "DELETE"}
	if err := st.StartRun(ctx, "run-1", scope, []policy.ActionRule{rule}); err != nil {
		t.Fatal(err)
	}
	p, err := policy.NewActionPolicy(scope, []policy.ActionRule{rule})
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.PlanTestWrite(ctx, "run-1", p.Classify(rule.Method, rule.URL))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MarkTestWritePossible(ctx, "run-1", id); err != nil {
		t.Fatal(err)
	}
	actions, err := st.TestActions(ctx, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	state := strconv.FormatInt(actions[0].StateEventID, 10)
	action := strconv.FormatInt(id, 10)
	if err := dataCommandAt(path, []string{"review-test-action", "run-1", action, "--state", "0"}); err == nil {
		t.Fatal("invalid review confirmation accepted")
	}
	scopeOutput := captureDataCommand(t, path, []string{"scope", "run-1"})
	before := captureDataCommand(t, path, []string{"test-actions", "run-1"})
	if !strings.Contains(before, "review=required") || !strings.Contains(before, "state-event="+state) {
		t.Fatalf("review flow missing current state: %s", before)
	}
	reviewOutput := captureDataCommand(t, path, []string{"review-test-action", "run-1", action, "--state", state})
	after := captureDataCommand(t, path, []string{"test-actions", "run-1"})
	if !strings.Contains(after, "review=acknowledged") || !strings.Contains(after, store.TestActionWritePossible) || !strings.Contains(reviewOutput, "Cleanup remains unresolved") {
		t.Fatalf("review closed obligation or was not shown: %s %s", reviewOutput, after)
	}
	for _, output := range []string{scopeOutput, before, reviewOutput, after} {
		if strings.Contains(output, "token=private") || strings.Contains(output, "/markers") {
			t.Fatalf("raw route leaked: %s", output)
		}
	}
}

func TestDataBackupAndRestoreUseRecoveredKeyThroughCLI(t *testing.T) {
	keyring.MockInit()
	root := t.TempDir()
	for _, name := range []string{"source", "archive", "custody"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(root, "source", "shadow.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Append(context.Background(), "run-1", "note", map[string]string{"value": "fixture"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "archive", "backup.sbk")
	keyFile := filepath.Join(root, "custody", "recovery.key")
	anchor := filepath.Join(root, "custody", "anchor.sha256")
	captureProtectedDataCommand(t, path, []string{"backup", archive, "--key-file", keyFile, "--anchor", anchor})
	keyring.MockInit() // a fresh machine has no evidence key yet
	restored := filepath.Join(root, "fresh-machine", "shadow.db")
	captureDataCommand(t, restored, []string{"restore", archive, "--key-file", keyFile, "--anchor", anchor})
	if output := captureDataCommand(t, restored, []string{"runs"}); !strings.Contains(output, "run-1") {
		t.Fatalf("restored run missing: %s", output)
	}
	if output := captureProtectedDataCommand(t, restored, []string{"audit-provenance"}); !strings.Contains(output, "Provenance audit") {
		t.Fatalf("restored provenance audit missing: %s", output)
	}
	if key, err := config.EvidenceKey(false); err != nil || len(key) != 32 {
		t.Fatalf("recovered key missing from keyring: %v", err)
	}
}

func TestPolicyValidateOnlyReadsOperatorRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	data := `{"version":1,"origin":"http://127.0.0.1:40123","actions":[{"url":"http://127.0.0.1:40123/safe","method":"GET","effect":"read"}]}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"policy", "validate", path, "--target", "http://127.0.0.1:40123"}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"policy", "validate", path, "--target", "http://127.0.0.1:40124"}); err == nil {
		t.Fatal("rules for a different exact origin accepted")
	}
}

func TestPolicyApprovalRequiresExactDigestAndDetectsRuleChanges(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	path, approvalPath := filepath.Join(dir, "rules.json"), filepath.Join(dir, "approval.json")
	origin := "http://127.0.0.1:40123"
	data := `{"version":1,"origin":"http://127.0.0.1:40123","actions":[{"url":"http://127.0.0.1:40123/safe","method":"GET","effect":"read"}]}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	plan, err := policy.ParseTrustedRules(strings.NewReader(data), origin)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := policy.TrustedRulesDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"policy", "approve", path, "--target", origin, "--confirm", strings.Repeat("0", 64), "--out", approvalPath}); err == nil {
		t.Fatal("wrong confirmation created an approval")
	}
	if _, err := os.Stat(approvalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("approval artifact was created without exact confirmation")
	}
	if err := run([]string{"policy", "approve", path, "--target", origin, "--confirm", digest, "--out", approvalPath}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"policy", "verify", path, "--target", origin, "--approval", approvalPath}); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(dir, "live-data")
	if err := run([]string{"target", "read", path, "--target", origin, "--approval", approvalPath, "--action", strings.Repeat("0", 64), "--data-dir", dataDir}); err == nil {
		t.Fatal("unapproved read action reached the gateway")
	}
	if _, err := os.Stat(dataDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid target action created run data")
	}
	if err := run([]string{"policy", "approve", path, "--target", origin, "--confirm", digest, "--out", approvalPath}); err == nil {
		t.Fatal("approval file was overwritten")
	}
	changed := strings.Replace(data, "/safe", "/other", 1)
	if err := os.WriteFile(path, []byte(changed), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"policy", "verify", path, "--target", origin, "--approval", approvalPath}); err == nil {
		t.Fatal("changed rules retained approval")
	}
}

func captureDataCommand(t *testing.T, path string, args []string) string {
	return captureDataCommandMode(t, path, args, false)
}

func captureProtectedDataCommand(t *testing.T, path string, args []string) string {
	return captureDataCommandMode(t, path, args, true)
}

func captureDataCommandMode(t *testing.T, path string, args []string, protected bool) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = w
	commandErr := dataCommandAtProtected(path, args, protected)
	os.Stdout = previous
	w.Close()
	output, readErr := io.ReadAll(r)
	r.Close()
	if commandErr != nil || readErr != nil {
		t.Fatalf("data %v: %v %v", args, commandErr, readErr)
	}
	return string(output)
}

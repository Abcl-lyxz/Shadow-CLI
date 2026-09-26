package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"shadow/internal/policy"
	"shadow/internal/store"
)

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

func captureDataCommand(t *testing.T, path string, args []string) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = w
	commandErr := dataCommandAt(path, args)
	os.Stdout = previous
	w.Close()
	output, readErr := io.ReadAll(r)
	r.Close()
	if commandErr != nil || readErr != nil {
		t.Fatalf("data %v: %v %v", args, commandErr, readErr)
	}
	return string(output)
}

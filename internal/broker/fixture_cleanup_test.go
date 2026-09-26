package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"shadow/internal/policy"
	"shadow/internal/store"
)

func setupFixtureCleanup(t *testing.T, handler http.Handler) (*store.Store, *FixtureCleanupExecutor, *FixtureDispatcher, policy.ActionRule, policy.ActionRule, func()) {
	t.Helper()
	server := httptest.NewServer(handler)
	st, err := store.OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), bytes.Repeat([]byte{9}, 32))
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	ctx := context.Background()
	scope, _ := policy.FromTarget(server.URL)
	write := policy.ActionRule{URL: server.URL + "/markers", Method: http.MethodPost, Effect: policy.EffectTestWrite, Resource: "shadow_marker_1", CleanupURL: server.URL + "/markers/shadow_marker_1", CleanupMethod: http.MethodDelete}
	read := policy.ActionRule{URL: write.CleanupURL, Method: http.MethodGet, Effect: policy.EffectRead}
	if err := st.StartRun(ctx, "run", scope, []policy.ActionRule{write, read}); err != nil {
		st.Close()
		server.Close()
		t.Fatal(err)
	}
	opts := Options{AllowLoopback: true, interval: time.Millisecond}
	executor, err := NewFixtureCleanupExecutor(ctx, st, "run", write, read, opts)
	if err != nil {
		st.Close()
		server.Close()
		t.Fatal(err)
	}
	return st, executor, executor.reader, write, read, func() { st.Close(); server.Close() }
}

func TestFixtureCleanupExecutesAndVerifiesNamedMarker(t *testing.T) {
	var present atomic.Bool
	present.Store(true) // fixture setup stands in for a separately dispatched write
	var deletes atomic.Int32
	st, executor, reader, write, read, closeAll := setupFixtureCleanup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/markers/shadow_marker_1" {
			t.Errorf("unexpected request %s", r.URL.Path)
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			if !present.Load() {
				w.WriteHeader(http.StatusNotFound)
			}
			fmt.Fprintf(w, `{"resource":"shadow_marker_1","present":%t}`, present.Load())
		case http.MethodDelete:
			deletes.Add(1)
			present.Store(false)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	}))
	defer closeAll()
	ctx := context.Background()
	policySet, _ := policy.NewActionPolicy(mustScope(t, write.URL), []policy.ActionRule{write})
	actionID, err := st.PlanTestWrite(ctx, "run", policySet.Classify(write.Method, write.URL))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MarkTestWritePossible(ctx, "run", actionID); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.fetcher.delete(ctx, read.URL); err == nil {
		t.Fatal("read fetcher accepted DELETE")
	}
	if _, _, err := executor.cleanup.get(ctx, read.URL); err == nil {
		t.Fatal("cleanup fetcher accepted GET")
	}
	_, beforeID, err := reader.GetRecorded(ctx, http.MethodGet, read.URL)
	if err != nil {
		t.Fatal(err)
	}
	afterID, err := executor.Cleanup(ctx, actionID, beforeID)
	if err != nil || afterID <= beforeID || deletes.Load() != 1 || present.Load() {
		t.Fatalf("fixture cleanup: after=%d err=%v deletes=%d present=%v", afterID, err, deletes.Load(), present.Load())
	}
	actions, err := st.TestActions(ctx, "run")
	if err != nil || len(actions) != 1 || actions[0].Status != store.TestActionFixtureVerified || actions[0].ObservationEventID != afterID {
		t.Fatalf("verified journal: %#v %v", actions, err)
	}
	if _, err := executor.Cleanup(ctx, actionID, beforeID); err == nil || deletes.Load() != 1 {
		t.Fatalf("cleanup replayed: %v deletes=%d", err, deletes.Load())
	}
	events, err := st.Events(ctx, "run")
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if strings.Contains(string(event.Payload), "/markers") {
			t.Fatalf("journal leaked route in event %d", event.ID)
		}
		if event.Kind == "fixture_cleanup_verified" {
			var payload struct {
				PresenceEventID int64 `json:"presence_event_id"`
				AbsenceEventID  int64 `json:"absence_event_id"`
			}
			if err := json.Unmarshal(event.Payload, &payload); err != nil || payload.PresenceEventID != beforeID || payload.AbsenceEventID != afterID {
				t.Fatalf("fixture verification lost evidence references: %#v %v", payload, err)
			}
		}
	}
}

func TestFixtureCleanupRejectsChangedOrUngrantedRules(t *testing.T) {
	var hits atomic.Int32
	st, _, _, write, read, closeAll := setupFixtureCleanup(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	defer closeAll()
	ctx := context.Background()
	changed := write
	changed.CleanupURL += "?other=1"
	for _, tc := range []struct {
		write policy.ActionRule
		read  policy.ActionRule
		opts  Options
	}{
		{changed, read, Options{AllowLoopback: true}},
		{write, policy.ActionRule{URL: write.URL, Method: http.MethodGet, Effect: policy.EffectRead}, Options{AllowLoopback: true}},
		{write, policy.ActionRule{URL: read.URL + "?other=1", Method: http.MethodGet, Effect: policy.EffectRead}, Options{AllowLoopback: true}},
		{write, read, Options{}},
	} {
		if _, err := NewFixtureCleanupExecutor(ctx, st, "run", tc.write, tc.read, tc.opts); err == nil {
			t.Fatal("accepted changed or ungranted fixture cleanup rule")
		}
	}
	if _, err := NewFixtureCleanupExecutor(ctx, st, "other-run", write, read, Options{AllowLoopback: true}); err == nil {
		t.Fatal("accepted cleanup for a different run")
	}
	if hits.Load() != 0 {
		t.Fatal("invalid executor reached fixture")
	}
}

func TestFixtureCleanupRejectsUnprovenAndRedirectedDeletes(t *testing.T) {
	var deletes, redirected atomic.Int32
	escape := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer escape.Close()
	st, executor, reader, write, read, closeAll := setupFixtureCleanup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletes.Add(1)
			http.Redirect(w, r, escape.URL+"/escape", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"resource":"shadow_marker_1","present":true}`))
	}))
	defer closeAll()
	ctx := context.Background()
	policySet, _ := policy.NewActionPolicy(mustScope(t, write.URL), []policy.ActionRule{write})
	_, earlyID, err := reader.GetRecorded(ctx, http.MethodGet, read.URL)
	if err != nil {
		t.Fatal(err)
	}
	actionID, err := st.PlanTestWrite(ctx, "run", policySet.Classify(write.Method, write.URL))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MarkTestWritePossible(ctx, "run", actionID); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Cleanup(ctx, actionID, earlyID); err == nil || deletes.Load() != 0 {
		t.Fatalf("early evidence authorized DELETE: %v", err)
	}
	_, beforeID, err := reader.GetRecorded(ctx, http.MethodGet, read.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Cleanup(ctx, actionID, beforeID); err == nil || deletes.Load() != 1 || redirected.Load() != 0 {
		t.Fatalf("redirected DELETE followed or accepted: %v deletes=%d escaped=%d", err, deletes.Load(), redirected.Load())
	}
	actions, err := st.TestActions(ctx, "run")
	if err != nil || len(actions) != 1 || actions[0].Status != store.TestActionCleanupAttempted {
		t.Fatalf("interrupted cleanup obligation lost: %#v %v", actions, err)
	}
}

func TestFixtureCleanupNeedsSemanticAbsence(t *testing.T) {
	var deletes atomic.Int32
	st, executor, reader, write, read, closeAll := setupFixtureCleanup(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deletes.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"resource":"shadow_marker_1","present":true}`))
	}))
	defer closeAll()
	ctx := context.Background()
	policySet, _ := policy.NewActionPolicy(mustScope(t, write.URL), []policy.ActionRule{write})
	actionID, err := st.PlanTestWrite(ctx, "run", policySet.Classify(write.Method, write.URL))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MarkTestWritePossible(ctx, "run", actionID); err != nil {
		t.Fatal(err)
	}
	_, beforeID, err := reader.GetRecorded(ctx, http.MethodGet, read.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Cleanup(ctx, actionID, beforeID); err == nil || deletes.Load() != 1 {
		t.Fatalf("presence after DELETE was verified: %v", err)
	}
	actions, err := st.TestActions(ctx, "run")
	if err != nil || len(actions) != 1 || actions[0].Status != store.TestActionCleanupObserved {
		t.Fatalf("incorrect semantic cleanup state: %#v %v", actions, err)
	}
}

func mustScope(t *testing.T, raw string) policy.Scope {
	t.Helper()
	scope, err := policy.FromTarget(raw)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

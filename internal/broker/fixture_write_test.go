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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"shadow/internal/policy"
	"shadow/internal/store"
)

func fixtureWriteRules(base string) (policy.ActionRule, policy.ActionRule) {
	write := policy.ActionRule{URL: base + "/markers", Method: http.MethodPost, Effect: policy.EffectTestWrite, Resource: "shadow_marker_1", CleanupURL: base + "/markers/shadow_marker_1", CleanupMethod: http.MethodDelete}
	return write, policy.ActionRule{URL: write.CleanupURL, Method: http.MethodGet, Effect: policy.EffectRead}
}

func fixtureWriteStore(t *testing.T, path, base string, key []byte) (*store.Store, policy.ActionRule, policy.ActionRule) {
	t.Helper()
	st, err := store.OpenWithEvidenceKey(path, key)
	if err != nil {
		t.Fatal(err)
	}
	write, read := fixtureWriteRules(base)
	encoded, err := json.Marshal(policy.TrustedRules{Version: 1, Origin: base, Actions: []policy.ActionRule{write, read}})
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := policy.ParseTrustedRules(bytes.NewReader(encoded), base)
	if err != nil {
		t.Fatal(err)
	}
	write, read = trusted.Actions[0], trusted.Actions[1]
	scope, err := policy.FromTarget(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.StartRun(context.Background(), "run", scope, trusted.Actions); err != nil {
		t.Fatal(err)
	}
	return st, write, read
}

func TestFixtureWriteCreatesOnlyNamedMarkerAndCleansIt(t *testing.T) {
	var present atomic.Bool
	var posts, deletes atomic.Int32
	var st *store.Store
	decisionBeforeMutation := func(method string) {
		t.Helper()
		events, err := st.Events(context.Background(), "run")
		if err != nil || len(events) == 0 || events[len(events)-1].Kind != "network_decision" {
			t.Errorf("%s reached fixture without a durable decision: %#v %v", method, events, err)
			return
		}
		var decision struct {
			Method  string `json:"method"`
			Allowed bool   `json:"allowed"`
		}
		if err := json.Unmarshal(events[len(events)-1].Payload, &decision); err != nil || decision.Method != method || !decision.Allowed {
			t.Errorf("%s arrived with wrong decision: %+v %v", method, decision, err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/markers/shadow_marker_1":
			if !present.Load() {
				w.WriteHeader(http.StatusNotFound)
			}
			fmt.Fprintf(w, `{"resource":"shadow_marker_1","present":%t}`, present.Load())
		case r.Method == http.MethodPost && r.URL.Path == "/markers":
			decisionBeforeMutation(http.MethodPost)
			posts.Add(1)
			var body struct {
				Resource string `json:"resource"`
			}
			if r.Header.Get("Content-Type") != "application/json" || json.NewDecoder(r.Body).Decode(&body) != nil || body.Resource != "shadow_marker_1" {
				t.Errorf("POST did not use the fixed marker contract")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			present.Store(true)
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"created":true}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/markers/shadow_marker_1":
			decisionBeforeMutation(http.MethodDelete)
			deletes.Add(1)
			present.Store(false)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected fixture request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer server.Close()
	key := bytes.Repeat([]byte{7}, 32)
	st, write, read := fixtureWriteStore(t, filepath.Join(t.TempDir(), "shadow.db"), server.URL, key)
	defer st.Close()
	ctx := context.Background()
	opts := Options{AllowLoopback: true, allowedURLs: []string{server.URL + "/unlisted"}, interval: time.Millisecond}
	d, err := newFixtureWriteDispatcher(ctx, st, "run", write, read, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.writer.delete(ctx, read.URL); err == nil {
		t.Fatal("write fetcher accepted DELETE")
	}
	if _, _, err := d.writer.get(ctx, read.URL); err == nil {
		t.Fatal("write fetcher accepted GET")
	}
	if _, err := d.writer.postMarker(ctx, write.URL, write.Resource); err == nil || posts.Load() != 0 {
		t.Fatalf("unjournaled POST reached fixture: %v", err)
	}
	actionID, presenceID, err := d.Dispatch(ctx)
	if err != nil || actionID <= 0 || presenceID <= 0 || posts.Load() != 1 || !present.Load() {
		t.Fatalf("fixture dispatch: action=%d evidence=%d posts=%d err=%v", actionID, presenceID, posts.Load(), err)
	}
	if _, err := d.writer.postMarker(context.WithValue(ctx, writeActionContextKey{}, actionID), write.URL, write.Resource); err == nil || posts.Load() != 1 {
		t.Fatalf("journaled POST was replayed: %v posts=%d", err, posts.Load())
	}
	if _, _, err := d.Dispatch(ctx); err == nil || posts.Load() != 1 {
		t.Fatalf("duplicate marker write reached fixture: %v", err)
	}
	if err := st.PurgeRun(ctx, "run"); err == nil {
		t.Fatal("purged possible fixture write before cleanup")
	}
	executor, err := newFixtureCleanupExecutor(ctx, st, "run", write, read, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Cleanup(ctx, actionID, presenceID); err != nil || deletes.Load() != 1 || present.Load() {
		t.Fatalf("fixture cleanup: deletes=%d err=%v", deletes.Load(), err)
	}
	actions, err := st.TestActions(ctx, "run")
	if err != nil || len(actions) != 1 || actions[0].Status != store.TestActionFixtureVerified {
		t.Fatalf("journal state: %#v %v", actions, err)
	}
	events, err := st.Events(ctx, "run")
	if err != nil {
		t.Fatal(err)
	}
	var responseLogged bool
	for _, event := range events {
		if strings.Contains(string(event.Payload), "/markers") || strings.Contains(string(event.Payload), "created") {
			t.Fatalf("raw fixture response or URL entered event %d", event.ID)
		}
		responseLogged = responseLogged || event.Kind == "fixture_write_response"
	}
	if !responseLogged {
		t.Fatal("fixture POST result was not journaled")
	}
	if err := st.PurgeRun(ctx, "run"); err != nil {
		t.Fatalf("verified fixture run could not be purged: %v", err)
	}
}

func TestFixtureCleanupRecoveryInspectsWithoutReplayingDelete(t *testing.T) {
	for _, absent := range []bool{true, false} {
		t.Run(fmt.Sprint("absent=", absent), func(t *testing.T) {
			var present atomic.Bool
			present.Store(true)
			var deletes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete {
					deletes.Add(1)
					w.WriteHeader(http.StatusNoContent)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if !present.Load() {
					w.WriteHeader(http.StatusNotFound)
				}
				fmt.Fprintf(w, `{"resource":"shadow_marker_1","present":%t}`, present.Load())
			}))
			defer server.Close()
			path := filepath.Join(t.TempDir(), "shadow.db")
			key := bytes.Repeat([]byte{8}, 32)
			st, write, read := fixtureWriteStore(t, path, server.URL, key)
			ctx := context.Background()
			policySet, _ := policy.NewActionPolicy(mustScope(t, server.URL), []policy.ActionRule{write})
			actionID, err := st.PlanFixtureTestWrite(ctx, "run", policySet.Classify(write.Method, write.URL))
			if err != nil {
				t.Fatal(err)
			}
			if err := st.MarkTestWritePossible(ctx, "run", actionID); err != nil {
				t.Fatal(err)
			}
			if err := st.Close(); err != nil {
				t.Fatal(err)
			}
			st, err = store.OpenWithEvidenceKey(path, key)
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			executor, err := newFixtureCleanupExecutor(ctx, st, "run", write, read, Options{AllowLoopback: true, interval: time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			presenceID, err := executor.InspectWrite(ctx, actionID)
			if err != nil || presenceID <= 0 {
				t.Fatalf("recovered write inspection: %d %v", presenceID, err)
			}
			if err := st.MarkCleanupAttempted(ctx, "run", actionID); err != nil {
				t.Fatal(err)
			}
			if absent {
				present.Store(false) // unknown prior DELETE result after crash
			}
			afterID, err := executor.InspectCleanup(ctx, actionID, presenceID)
			if afterID <= presenceID || (err == nil) != absent || deletes.Load() != 0 {
				t.Fatalf("read-only recovery: after=%d err=%v deletes=%d", afterID, err, deletes.Load())
			}
			actions, err := st.TestActions(ctx, "run")
			if err != nil || len(actions) != 1 {
				t.Fatalf("recovery journal: %#v %v", actions, err)
			}
			want := store.TestActionCleanupObserved
			if absent {
				want = store.TestActionFixtureVerified
			}
			if actions[0].Status != want {
				t.Fatalf("recovery status=%s want=%s", actions[0].Status, want)
			}
			if _, err := executor.InspectCleanup(ctx, actionID, presenceID); err == nil || deletes.Load() != 0 {
				t.Fatalf("replayed cleanup inspection: %v deletes=%d", err, deletes.Load())
			}
		})
	}
}

func TestFixtureWriteInFlightCannotLoseCleanupJournalToPurge(t *testing.T) {
	var present atomic.Bool
	postStarted := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releasePost := func() { releaseOnce.Do(func() { close(release) }) }
	defer releasePost()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			if !present.Load() {
				w.WriteHeader(http.StatusNotFound)
			}
			fmt.Fprintf(w, `{"resource":"shadow_marker_1","present":%t}`, present.Load())
		case http.MethodPost:
			present.Store(true)
			close(postStarted)
			<-release
			w.WriteHeader(http.StatusCreated)
		case http.MethodDelete:
			present.Store(false)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	st, write, read := fixtureWriteStore(t, filepath.Join(t.TempDir(), "shadow.db"), server.URL, bytes.Repeat([]byte{5}, 32))
	defer st.Close()
	ctx := context.Background()
	opts := Options{AllowLoopback: true, interval: time.Millisecond}
	d, err := newFixtureWriteDispatcher(ctx, st, "run", write, read, opts)
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		actionID, presenceID int64
		err                  error
	}
	done := make(chan outcome, 1)
	go func() {
		actionID, presenceID, err := d.Dispatch(ctx)
		done <- outcome{actionID, presenceID, err}
	}()
	select {
	case <-postStarted:
	case <-time.After(10 * time.Second):
		releasePost()
		t.Fatal("fixture POST did not start")
	}
	if err := st.PurgeRun(ctx, "run"); err == nil {
		releasePost()
		t.Fatal("purged a run while fixture POST was in flight")
	}
	releasePost()
	result := <-done
	if result.err != nil || result.actionID <= 0 || result.presenceID <= 0 {
		t.Fatalf("in-flight dispatch lost its journal: %#v", result)
	}
	executor, err := newFixtureCleanupExecutor(ctx, st, "run", write, read, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Cleanup(ctx, result.actionID, result.presenceID); err != nil {
		t.Fatal(err)
	}
}

func TestFixtureWriteRejectsChangedRulesAndRedirects(t *testing.T) {
	var posts, escaped atomic.Int32
	escape := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { escaped.Add(1) }))
	defer escape.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"resource":"shadow_marker_1","present":false}`))
			return
		}
		posts.Add(1)
		http.Redirect(w, r, escape.URL+"/outside", http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	st, write, read := fixtureWriteStore(t, filepath.Join(t.TempDir(), "shadow.db"), server.URL, bytes.Repeat([]byte{6}, 32))
	defer st.Close()
	ctx := context.Background()
	opts := Options{AllowLoopback: true, interval: time.Millisecond}
	changed := write
	changed.Resource = "shadow_other"
	for _, tc := range []struct {
		write policy.ActionRule
		read  policy.ActionRule
		opts  Options
	}{
		{changed, read, opts},
		{write, policy.ActionRule{URL: read.URL + "?other=1", Method: http.MethodGet, Effect: policy.EffectRead}, opts},
		{write, read, Options{}},
	} {
		if _, err := newFixtureWriteDispatcher(ctx, st, "run", tc.write, tc.read, tc.opts); err == nil {
			t.Fatal("accepted changed or non-loopback write rule")
		}
	}
	if _, err := newFixtureWriteDispatcher(ctx, st, "other", write, read, opts); err == nil {
		t.Fatal("accepted wrong run")
	}
	d, err := newFixtureWriteDispatcher(ctx, st, "run", write, read, opts)
	if err != nil {
		t.Fatal(err)
	}
	actionID, _, err := d.Dispatch(ctx)
	if err == nil || actionID <= 0 || posts.Load() != 1 || escaped.Load() != 0 {
		t.Fatalf("redirected write was followed or accepted: action=%d err=%v posts=%d escaped=%d", actionID, err, posts.Load(), escaped.Load())
	}
	actions, err := st.TestActions(ctx, "run")
	if err != nil || len(actions) != 1 || actions[0].Status != store.TestActionWritePossible {
		t.Fatalf("redirect lost cleanup obligation: %#v %v", actions, err)
	}
	executor, err := newFixtureCleanupExecutor(ctx, st, "run", write, read, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executor.InspectWrite(ctx, actionID); err == nil || posts.Load() != 1 {
		t.Fatalf("absent marker was treated as a successful write: %v posts=%d", err, posts.Load())
	}
	if _, _, err := d.Dispatch(ctx); err == nil || posts.Load() != 1 {
		t.Fatalf("interrupted write replayed: %v posts=%d", err, posts.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := d.Dispatch(ctx); err == nil || posts.Load() != 1 {
		t.Fatalf("cancelled write reached fixture: %v", err)
	}
}

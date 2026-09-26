package broker

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"shadow/internal/policy"
	"shadow/internal/store"
)

func TestFixtureDispatcherEnforcesTrustedReadRules(t *testing.T) {
	var hits, escaped atomic.Int32
	escape := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { escaped.Add(1) }))
	defer escape.Close()
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/safe", http.StatusFound)
		case "/hidden":
			http.Redirect(w, r, "/unlisted", http.StatusFound)
		case "/escape":
			http.Redirect(w, r, escape.URL+"/outside", http.StatusFound)
		default:
			w.Write([]byte("fixture"))
		}
	}))
	defer fixture.Close()
	scope, err := policy.FromTarget(fixture.URL)
	if err != nil {
		t.Fatal(err)
	}
	rules := []policy.ActionRule{
		{URL: fixture.URL + "/start", Method: "GET", Effect: policy.EffectRead},
		{URL: fixture.URL + "/safe", Method: "GET", Effect: policy.EffectRead},
		{URL: fixture.URL + "/hidden", Method: "GET", Effect: policy.EffectRead},
		{URL: fixture.URL + "/escape", Method: "GET", Effect: policy.EffectRead},
		{URL: fixture.URL + "/blocked", Method: "GET", Effect: policy.EffectBlocked},
		{URL: fixture.URL + "/login", Method: "POST", Effect: policy.EffectAuth},
		{URL: fixture.URL + "/markers", Method: "POST", Effect: policy.EffectTestWrite, Resource: "shadow_marker_1", CleanupURL: fixture.URL + "/markers/shadow_marker_1", CleanupMethod: "DELETE"},
	}
	st, err := store.OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.StartRun(context.Background(), "fixture-run", scope, rules); err != nil {
		t.Fatal(err)
	}
	d, err := NewFixtureDispatcher(context.Background(), st, "fixture-run", rules, Options{AllowLoopback: true, AllowedURLs: []string{fixture.URL + "/unlisted"}, interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if obs, err := d.Get(context.Background(), "GET", fixture.URL+"/start"); err != nil || obs.Status != http.StatusOK || hits.Load() != 2 {
		t.Fatalf("allowed redirect: %#v %v hits=%d", obs, err, hits.Load())
	}
	before := hits.Load()
	for _, tc := range []struct{ method, url string }{
		{"GET", fixture.URL + "/unlisted"},
		{"GET", fixture.URL + "/blocked"},
		{"POST", fixture.URL + "/login"},
		{"POST", fixture.URL + "/markers"},
		{"HEAD", fixture.URL + "/safe"},
		{"GET", fixture.URL + "/safe?mutation=1"},
		{"GET", escape.URL + "/outside"},
	} {
		if _, err := d.Get(context.Background(), tc.method, tc.url); err == nil {
			t.Errorf("allowed %s %s", tc.method, tc.url)
		}
	}
	if hits.Load() != before {
		t.Fatalf("denied request reached fixture: %d -> %d", before, hits.Load())
	}
	if _, err := d.Get(context.Background(), "GET", fixture.URL+"/hidden"); err == nil || hits.Load() != before+1 {
		t.Fatalf("unlisted redirect followed: %v hits=%d", err, hits.Load())
	}
	if _, err := d.Get(context.Background(), "GET", fixture.URL+"/escape"); err == nil || escaped.Load() != 0 {
		t.Fatalf("cross-origin redirect followed: %v escaped=%d", err, escaped.Load())
	}
	if _, id, err := d.GetRecorded(context.Background(), "GET", fixture.URL+"/safe"); err != nil || id <= 0 {
		t.Fatalf("recorded fixture read: id=%d err=%v", id, err)
	}
	if _, _, err := d.GetRecorded(context.Background(), "POST", fixture.URL+"/markers"); err == nil {
		t.Fatal("test write reached recorded dispatcher")
	}
	d.fetcher.interval = time.Hour
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	before = hits.Load()
	if _, err := d.Get(cancelled, "GET", fixture.URL+"/safe"); err == nil || hits.Load() != before {
		t.Fatalf("cancelled request reached fixture: %v hits=%d", err, hits.Load())
	}
}

func TestFixtureDispatcherRequiresReadRoute(t *testing.T) {
	ctx := context.Background()
	scope, _ := policy.FromTarget("http://fixture.test")
	st, err := store.Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	login := policy.ActionRule{URL: scope.Origin + "/login", Method: "POST", Effect: policy.EffectAuth}
	read := policy.ActionRule{URL: scope.Origin + "/safe", Method: "GET", Effect: policy.EffectRead}
	if err := st.StartRun(ctx, "fixture-run", scope, []policy.ActionRule{login, read}); err != nil {
		t.Fatal(err)
	}
	_, err = NewFixtureDispatcher(ctx, st, "fixture-run", []policy.ActionRule{login}, Options{AllowLoopback: true})
	if err == nil {
		t.Fatal("dispatcher without read route accepted")
	}
	_, err = NewFixtureDispatcher(ctx, st, "fixture-run", []policy.ActionRule{read}, Options{AllowLoopback: true, lookup: func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8")}, nil
	}})
	if err == nil {
		t.Fatal("public destination accepted as fixture")
	}
}

func TestFixtureDispatcherRejectsRunAndGrantMismatches(t *testing.T) {
	ctx := context.Background()
	var hits atomic.Int32
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("fixture"))
	}))
	defer fixture.Close()
	scope, _ := policy.FromTarget(fixture.URL)
	read := policy.ActionRule{URL: fixture.URL + "/safe", Method: http.MethodGet, Effect: policy.EffectRead}
	st, err := store.OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.StartRun(ctx, "granted", scope, []policy.ActionRule{read}); err != nil {
		t.Fatal(err)
	}
	if err := st.StartRun(ctx, "other", scope, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.Append(ctx, "legacy", "started", map[string]string{"scope": scope.Origin}); err != nil {
		t.Fatal(err)
	}
	for _, runID := range []string{"missing", "legacy", "other"} {
		if _, err := NewFixtureDispatcher(ctx, st, runID, []policy.ActionRule{read}, Options{AllowLoopback: true}); err == nil {
			t.Errorf("run %q gained a read grant", runID)
		}
	}
	for _, rule := range []policy.ActionRule{
		{URL: fixture.URL + "/extra", Method: http.MethodGet, Effect: policy.EffectRead},
		{URL: read.URL, Method: http.MethodHead, Effect: policy.EffectRead},
		{URL: read.URL, Method: http.MethodGet, Effect: policy.EffectBlocked},
	} {
		if _, err := NewFixtureDispatcher(ctx, st, "granted", []policy.ActionRule{rule}, Options{AllowLoopback: true}); err == nil {
			t.Errorf("mismatched grant accepted: %#v", rule)
		}
	}
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer other.Close()
	if _, err := NewFixtureDispatcher(ctx, st, "granted", []policy.ActionRule{{URL: other.URL + "/safe", Method: http.MethodGet, Effect: policy.EffectRead}}, Options{AllowLoopback: true}); err == nil {
		t.Fatal("different-origin route accepted")
	}
	if hits.Load() != 0 {
		t.Fatal("denied constructor reached a fixture")
	}
	d, err := NewFixtureDispatcher(ctx, st, "granted", []policy.ActionRule{read}, Options{AllowLoopback: true, interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PurgeRun(ctx, "granted"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Get(ctx, http.MethodGet, read.URL); err == nil {
		t.Fatal("purged run dispatched a fixture request")
	}
	if err := st.StartRun(ctx, "granted", scope, []policy.ActionRule{read}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.GetRecorded(ctx, http.MethodGet, read.URL); err == nil {
		t.Fatal("reused run inherited the old dispatcher")
	}
	if hits.Load() != 0 {
		t.Fatal("state mismatch reached a fixture")
	}
}

func TestFixtureDispatcherChecksSnapshotBeforeRedirect(t *testing.T) {
	ctx := context.Background()
	var st *store.Store
	var hits atomic.Int32
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/start" {
			if err := st.PurgeRun(ctx, "fixture-run"); err != nil {
				t.Errorf("purge during fixture response: %v", err)
			}
			http.Redirect(w, r, "/safe", http.StatusFound)
		}
	}))
	defer fixture.Close()
	scope, _ := policy.FromTarget(fixture.URL)
	rules := []policy.ActionRule{
		{URL: fixture.URL + "/start", Method: http.MethodGet, Effect: policy.EffectRead},
		{URL: fixture.URL + "/safe", Method: http.MethodGet, Effect: policy.EffectRead},
	}
	var err error
	st, err = store.Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.StartRun(ctx, "fixture-run", scope, rules); err != nil {
		t.Fatal(err)
	}
	d, err := NewFixtureDispatcher(ctx, st, "fixture-run", rules, Options{AllowLoopback: true, interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Get(ctx, http.MethodGet, fixture.URL+"/start"); err == nil || hits.Load() != 1 {
		t.Fatalf("redirect after purge: err=%v hits=%d", err, hits.Load())
	}
}

func TestFixtureDispatcherRejectsEvidenceAfterRunPurge(t *testing.T) {
	ctx := context.Background()
	var st *store.Store
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := st.PurgeRun(ctx, "fixture-run"); err != nil {
			t.Errorf("purge during fixture response: %v", err)
		}
		w.Write([]byte("fixture"))
	}))
	defer fixture.Close()
	scope, _ := policy.FromTarget(fixture.URL)
	read := policy.ActionRule{URL: fixture.URL + "/safe", Method: http.MethodGet, Effect: policy.EffectRead}
	var err error
	st, err = store.OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), bytes.Repeat([]byte{6}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.StartRun(ctx, "fixture-run", scope, []policy.ActionRule{read}); err != nil {
		t.Fatal(err)
	}
	d, err := NewFixtureDispatcher(ctx, st, "fixture-run", []policy.ActionRule{read}, Options{AllowLoopback: true, interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, id, err := d.GetRecorded(ctx, http.MethodGet, read.URL); err == nil || id != 0 {
		t.Fatalf("stale fixture response was recorded: id=%d err=%v", id, err)
	}
	events, err := st.Events(ctx, "fixture-run")
	if err != nil || len(events) != 0 {
		t.Fatalf("purged run received a new event: %#v %v", events, err)
	}
}

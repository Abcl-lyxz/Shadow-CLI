package broker

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestFixtureTypedReadRecordsHashedDecisionBeforeDispatch(t *testing.T) {
	ctx := context.Background()
	var st *store.Store
	var hits atomic.Int32
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		events, err := st.Events(ctx, "run")
		if err != nil || len(events) != 2 || events[1].Kind != "network_decision" {
			t.Errorf("request arrived without a durable decision: %#v %v", events, err)
		}
		w.Write([]byte("fixture"))
	}))
	defer fixture.Close()
	scope, _ := policy.FromTarget(fixture.URL)
	rule := policy.ActionRule{URL: fixture.URL + "/safe?token=private", Method: http.MethodGet, Effect: policy.EffectRead}
	var err error
	st, err = store.OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), bytes.Repeat([]byte{0x52}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.StartRun(ctx, "run", scope, []policy.ActionRule{rule}); err != nil {
		t.Fatal(err)
	}
	d, err := newFixtureDispatcher(ctx, st, "run", []policy.ActionRule{rule}, Options{AllowLoopback: true, interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	id := ReadActionID(rule)
	if ids := d.ReadActionIDs(); len(ids) != 1 || ids[0] != id {
		t.Fatalf("typed read catalog: %v", ids)
	}
	if _, eventID, err := d.ReadRecorded(ctx, id); err != nil || eventID <= 0 || hits.Load() != 1 {
		t.Fatalf("typed read failed: event=%d hits=%d err=%v", eventID, hits.Load(), err)
	}
	if _, _, err := d.ReadRecorded(ctx, ReadActionID(policy.ActionRule{URL: fixture.URL + "/other", Method: http.MethodGet, Effect: policy.EffectRead})); err == nil || hits.Load() != 1 {
		t.Fatalf("ungranted action dispatched: hits=%d err=%v", hits.Load(), err)
	}
	if _, err := d.getUnrecorded(ctx, http.MethodGet, fixture.URL+"/other"); err == nil || hits.Load() != 1 {
		t.Fatalf("unlisted route dispatched: hits=%d err=%v", hits.Load(), err)
	}
	events, err := st.Events(ctx, "run")
	if err != nil || len(events) != 4 || events[1].Kind != "network_decision" || events[3].Kind != "network_decision" {
		t.Fatalf("network decisions missing: %#v %v", events, err)
	}
	for _, event := range []store.Event{events[1], events[3]} {
		if bytes.Contains(event.Payload, []byte("private")) || bytes.Contains(event.Payload, []byte("/safe")) || bytes.Contains(event.Payload, []byte("/other")) {
			t.Fatalf("decision leaked URL data: %s", event.Payload)
		}
	}
	var allowed, denied struct {
		Allowed bool   `json:"allowed"`
		Hash    string `json:"url_sha256"`
	}
	if err := json.Unmarshal(events[1].Payload, &allowed); err != nil || !allowed.Allowed || allowed.Hash != routeDigest(rule.URL) {
		t.Fatalf("allowed decision: %+v %v", allowed, err)
	}
	if err := json.Unmarshal(events[3].Payload, &denied); err != nil || denied.Allowed || denied.Hash != routeDigest(fixture.URL+"/other") {
		t.Fatalf("denied decision: %+v %v", denied, err)
	}
}

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
	d, err := newFixtureDispatcher(context.Background(), st, "fixture-run", rules, Options{AllowLoopback: true, allowedURLs: []string{fixture.URL + "/unlisted"}, interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if obs, err := d.getUnrecorded(context.Background(), "GET", fixture.URL+"/start"); err != nil || obs.Status != http.StatusOK || hits.Load() != 2 {
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
		if _, err := d.getUnrecorded(context.Background(), tc.method, tc.url); err == nil {
			t.Errorf("allowed %s %s", tc.method, tc.url)
		}
	}
	if hits.Load() != before {
		t.Fatalf("denied request reached fixture: %d -> %d", before, hits.Load())
	}
	if _, err := d.getUnrecorded(context.Background(), "GET", fixture.URL+"/hidden"); err == nil || hits.Load() != before+1 {
		t.Fatalf("unlisted redirect followed: %v hits=%d", err, hits.Load())
	}
	if _, err := d.getUnrecorded(context.Background(), "GET", fixture.URL+"/escape"); err == nil || escaped.Load() != 0 {
		t.Fatalf("cross-origin redirect followed: %v escaped=%d", err, escaped.Load())
	}
	events, err := st.Events(context.Background(), "fixture-run")
	if err != nil {
		t.Fatal(err)
	}
	redirectDenied := false
	for _, event := range events {
		if event.Kind != "network_decision" {
			continue
		}
		var decision struct {
			URLSHA256 string `json:"url_sha256"`
			Allowed   bool   `json:"allowed"`
		}
		if err := json.Unmarshal(event.Payload, &decision); err != nil {
			t.Fatal(err)
		}
		if decision.URLSHA256 == routeDigest(escape.URL+"/outside") && !decision.Allowed {
			redirectDenied = true
		}
	}
	if !redirectDenied {
		t.Fatal("cross-origin redirect denial was not recorded")
	}
	if _, id, err := d.getRecorded(context.Background(), "GET", fixture.URL+"/safe"); err != nil || id <= 0 {
		t.Fatalf("recorded fixture read: id=%d err=%v", id, err)
	}
	if _, _, err := d.getRecorded(context.Background(), "POST", fixture.URL+"/markers"); err == nil {
		t.Fatal("test write reached recorded dispatcher")
	}
	d.fetcher.interval = time.Hour
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	before = hits.Load()
	if _, err := d.getUnrecorded(cancelled, "GET", fixture.URL+"/safe"); err == nil || hits.Load() != before {
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
	_, err = newFixtureDispatcher(ctx, st, "fixture-run", []policy.ActionRule{login}, Options{AllowLoopback: true})
	if err == nil {
		t.Fatal("dispatcher without read route accepted")
	}
	_, err = newFixtureDispatcher(ctx, st, "fixture-run", []policy.ActionRule{read}, Options{AllowLoopback: true, lookup: func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8")}, nil
	}})
	if err == nil {
		t.Fatal("public destination accepted as fixture")
	}
}

func TestFixtureRecordedReadRequiresEvidenceKeyBeforeNetwork(t *testing.T) {
	var hits atomic.Int32
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("fixture"))
	}))
	defer fixture.Close()
	ctx := context.Background()
	scope, _ := policy.FromTarget(fixture.URL)
	read := policy.ActionRule{URL: fixture.URL + "/safe", Method: http.MethodGet, Effect: policy.EffectRead}
	st, err := store.Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.StartRun(ctx, "run", scope, []policy.ActionRule{read}); err != nil {
		t.Fatal(err)
	}
	d, err := newFixtureDispatcher(ctx, st, "run", []policy.ActionRule{read}, Options{AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, id, err := d.getRecorded(ctx, http.MethodGet, read.URL); err == nil || id != 0 || hits.Load() != 0 {
		t.Fatalf("read without evidence key reached fixture: id=%d err=%v hits=%d", id, err, hits.Load())
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
		if _, err := newFixtureDispatcher(ctx, st, runID, []policy.ActionRule{read}, Options{AllowLoopback: true}); err == nil {
			t.Errorf("run %q gained a read grant", runID)
		}
	}
	for _, rule := range []policy.ActionRule{
		{URL: fixture.URL + "/extra", Method: http.MethodGet, Effect: policy.EffectRead},
		{URL: read.URL, Method: http.MethodHead, Effect: policy.EffectRead},
		{URL: read.URL, Method: http.MethodGet, Effect: policy.EffectBlocked},
	} {
		if _, err := newFixtureDispatcher(ctx, st, "granted", []policy.ActionRule{rule}, Options{AllowLoopback: true}); err == nil {
			t.Errorf("mismatched grant accepted: %#v", rule)
		}
	}
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer other.Close()
	if _, err := newFixtureDispatcher(ctx, st, "granted", []policy.ActionRule{{URL: other.URL + "/safe", Method: http.MethodGet, Effect: policy.EffectRead}}, Options{AllowLoopback: true}); err == nil {
		t.Fatal("different-origin route accepted")
	}
	if hits.Load() != 0 {
		t.Fatal("denied constructor reached a fixture")
	}
	d, err := newFixtureDispatcher(ctx, st, "granted", []policy.ActionRule{read}, Options{AllowLoopback: true, interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PurgeRun(ctx, "granted"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.getUnrecorded(ctx, http.MethodGet, read.URL); err == nil {
		t.Fatal("purged run dispatched a fixture request")
	}
	if err := st.StartRun(ctx, "granted", scope, []policy.ActionRule{read}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.getRecorded(ctx, http.MethodGet, read.URL); err == nil {
		t.Fatal("reused run inherited the old dispatcher")
	}
	if hits.Load() != 0 {
		t.Fatal("state mismatch reached a fixture")
	}
}

func TestFixtureDispatcherRejectsPurgeDuringRedirectHop(t *testing.T) {
	ctx := context.Background()
	var st *store.Store
	var hits atomic.Int32
	var purgeBlocked atomic.Bool
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/start" {
			if err := st.PurgeRun(ctx, "fixture-run"); err != nil {
				purgeBlocked.Store(true)
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
	d, err := newFixtureDispatcher(ctx, st, "fixture-run", rules, Options{AllowLoopback: true, interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.getUnrecorded(ctx, http.MethodGet, fixture.URL+"/start"); err != nil || hits.Load() != 2 || !purgeBlocked.Load() {
		t.Fatalf("in-flight redirect lost its run: err=%v hits=%d purge-blocked=%t", err, hits.Load(), purgeBlocked.Load())
	}
	if err := st.PurgeRun(ctx, "fixture-run"); err != nil {
		t.Fatalf("completed redirect still blocked purge: %v", err)
	}
}

func TestFixtureDispatcherRejectsPurgeDuringEvidenceRequest(t *testing.T) {
	ctx := context.Background()
	var st *store.Store
	var purgeBlocked atomic.Bool
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := st.PurgeRun(ctx, "fixture-run"); err != nil {
			purgeBlocked.Store(true)
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
	d, err := newFixtureDispatcher(ctx, st, "fixture-run", []policy.ActionRule{read}, Options{AllowLoopback: true, interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, id, err := d.getRecorded(ctx, http.MethodGet, read.URL); err != nil || id <= 0 || !purgeBlocked.Load() {
		t.Fatalf("in-flight evidence lost its run: id=%d err=%v purge-blocked=%t", id, err, purgeBlocked.Load())
	}
	events, err := st.Events(ctx, "fixture-run")
	if err != nil || len(events) != 3 || events[1].Kind != "network_decision" || events[2].Kind != "observation" {
		t.Fatalf("recorded request lost its evidence event: %#v %v", events, err)
	}
	if err := st.PurgeRun(ctx, "fixture-run"); err != nil {
		t.Fatalf("completed evidence request still blocked purge: %v", err)
	}
}

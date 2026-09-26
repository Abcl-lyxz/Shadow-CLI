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
	d, err := NewFixtureDispatcher(context.Background(), scope, rules, Options{AllowLoopback: true, AllowedURLs: []string{fixture.URL + "/unlisted"}, interval: time.Millisecond})
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
	st, err := store.OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, id, err := d.GetRecorded(context.Background(), "GET", "fixture-run", fixture.URL+"/safe", st); err != nil || id <= 0 {
		t.Fatalf("recorded fixture read: id=%d err=%v", id, err)
	}
	if _, _, err := d.GetRecorded(context.Background(), "POST", "fixture-run", fixture.URL+"/markers", st); err == nil {
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
	scope, _ := policy.FromTarget("http://fixture.test")
	_, err := NewFixtureDispatcher(context.Background(), scope, []policy.ActionRule{{URL: scope.Origin + "/login", Method: "POST", Effect: policy.EffectAuth}}, Options{AllowLoopback: true})
	if err == nil {
		t.Fatal("dispatcher without read route accepted")
	}
	read := []policy.ActionRule{{URL: scope.Origin + "/safe", Method: "GET", Effect: policy.EffectRead}}
	_, err = NewFixtureDispatcher(context.Background(), scope, read, Options{AllowLoopback: true, lookup: func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8")}, nil
	}})
	if err == nil {
		t.Fatal("public destination accepted as fixture")
	}
}

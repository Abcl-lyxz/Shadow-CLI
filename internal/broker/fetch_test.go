package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"shadow/internal/policy"
	"shadow/internal/store"
)

func fixtureFetcher(t *testing.T, origin string, paths ...string) *fetcher {
	t.Helper()
	scope, err := policy.FromTarget(origin)
	if err != nil {
		t.Fatal(err)
	}
	allowed := make([]string, len(paths))
	for i, path := range paths {
		allowed[i] = origin + path
	}
	f, err := newFetcher(context.Background(), scope, Options{allowedURLs: allowed, AllowLoopback: true, interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFixtureGatewayScopeRedirectsAndMinimizedEvidence(t *testing.T) {
	var escaped atomic.Int32
	escape := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { escaped.Add(1) }))
	defer escape.Close()
	var fixture *httptest.Server
	fixture = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/safe?token=secret123", http.StatusFound)
		case "/safe":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			io.WriteString(w, "private@example.com api_key=secret123")
		case "/unknown":
			w.Header().Set("Content-Type", "application/x-private-48217")
			io.WriteString(w, "safe")
		case "/escape":
			http.Redirect(w, r, escape.URL+"/hit", http.StatusFound)
		case "/hidden":
			http.Redirect(w, r, "/unlisted", http.StatusFound)
		case "/unlisted":
			t.Error("unlisted path reached fixture")
		}
	}))
	defer fixture.Close()
	f := fixtureFetcher(t, fixture.URL, "/start", "/safe?token=secret123", "/escape", "/hidden", "/unknown")
	result, err := f.getObservation(context.Background(), fixture.URL+"/start")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != 200 || result.Bytes == 0 || result.SHA256 == "" || result.URLSHA256 == "" || result.ContentType != "text/plain" {
		t.Fatalf("unexpected observation: %#v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"secret123", "private@example.com", "/safe", "token="} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("observation leaked %q: %s", secret, encoded)
		}
	}
	unknown, err := f.getObservation(context.Background(), fixture.URL+"/unknown")
	if err != nil || unknown.ContentType != "" {
		t.Fatalf("unknown free-form MIME reached observation: %q %v", unknown.ContentType, err)
	}
	for _, raw := range []string{fixture.URL + "/unlisted", fixture.URL + "/safe?token=other", fixture.URL + "/safe#fragment", escape.URL + "/hit"} {
		if _, err := f.getObservation(context.Background(), raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	if _, err := f.getObservation(context.Background(), fixture.URL+"/escape"); err == nil || escaped.Load() != 0 {
		t.Fatalf("cross-origin redirect was followed: err=%v hits=%d", err, escaped.Load())
	}
	if _, err := f.getObservation(context.Background(), fixture.URL+"/hidden"); err == nil {
		t.Fatal("unlisted same-origin redirect was followed")
	}
}

func TestFixtureGatewayBudgetAndBodyCap(t *testing.T) {
	var hits atomic.Int32
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/octet-stream")
		io.WriteString(w, strings.Repeat("x", maxBody+100))
	}))
	defer fixture.Close()
	f := fixtureFetcher(t, fixture.URL, "/large")
	f.requestLimit = 2
	for i := 0; i < 2; i++ {
		result, err := f.getObservation(context.Background(), fixture.URL+"/large")
		if err != nil {
			t.Fatal(err)
		}
		if !result.Truncated || result.Bytes != maxBody {
			t.Fatalf("body cap: %#v", result)
		}
	}
	if _, err := f.getObservation(context.Background(), fixture.URL+"/large"); err == nil || hits.Load() != 2 {
		t.Fatalf("request budget not enforced: err=%v hits=%d", err, hits.Load())
	}
}

func TestFixtureGatewayRedirectLimitConsumesBudget(t *testing.T) {
	var hits atomic.Int32
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	defer fixture.Close()
	f := fixtureFetcher(t, fixture.URL, "/loop")
	f.requestLimit = maxRedirects + 1
	if _, err := f.getObservation(context.Background(), fixture.URL+"/loop"); err == nil || hits.Load() != maxRedirects+1 {
		t.Fatalf("redirect limit: err=%v hits=%d", err, hits.Load())
	}
	if _, err := f.getObservation(context.Background(), fixture.URL+"/loop"); err == nil || hits.Load() != maxRedirects+1 {
		t.Fatalf("redirects were not budgeted: err=%v hits=%d", err, hits.Load())
	}
}

func TestFixtureGatewayPinsDNSAndSerializesRequests(t *testing.T) {
	var active, maximum, hits atomic.Int32
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		for {
			old := maximum.Load()
			if n <= old || maximum.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		hits.Add(1)
		active.Add(-1)
		io.WriteString(w, "ok")
	}))
	defer fixture.Close()
	fixtureURL, _ := url.Parse(fixture.URL)
	port := fixtureURL.Port()
	scope, err := policy.FromTarget("http://rebind.test:" + port)
	if err != nil {
		t.Fatal(err)
	}
	var lookups atomic.Int32
	f, err := newFetcher(context.Background(), scope, Options{
		allowedURLs: []string{scope.Origin + "/safe"}, AllowLoopback: true, interval: time.Millisecond,
		lookup: func(context.Context, string) ([]net.IP, error) {
			if lookups.Add(1) == 1 {
				return []net.IP{net.ParseIP("127.0.0.1")}, nil
			}
			return []net.IP{net.ParseIP("127.0.0.2")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.getObservation(context.Background(), scope.Origin+"/safe"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if lookups.Load() != 1 || hits.Load() != 3 || maximum.Load() != 1 {
		t.Fatalf("DNS or concurrency policy failed: lookups=%d hits=%d max=%d", lookups.Load(), hits.Load(), maximum.Load())
	}
}

func TestFixtureGatewayRejectsUnsafeDestinationsAndMissingAllowlist(t *testing.T) {
	for _, tc := range []struct {
		ips           []net.IP
		allowLoopback bool
	}{
		{[]net.IP{net.ParseIP("127.0.0.1")}, false},
		{[]net.IP{net.ParseIP("10.0.0.1")}, true},
		{[]net.IP{net.ParseIP("100.100.100.200")}, false},
		{[]net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("127.0.0.1")}, false},
	} {
		scope, _ := policy.FromTarget("http://fixture.test")
		_, err := newFetcher(context.Background(), scope, Options{allowedURLs: []string{scope.Origin + "/safe"}, AllowLoopback: tc.allowLoopback, lookup: func(context.Context, string) ([]net.IP, error) { return tc.ips, nil }})
		if err == nil {
			t.Errorf("accepted destinations %v", tc.ips)
		}
	}
	scope, _ := policy.FromTarget("http://fixture.test")
	if _, err := newFetcher(context.Background(), scope, Options{}); err == nil {
		t.Fatal("missing allowlist accepted")
	}
}

func TestFixtureGatewayCancellationWhileWaiting(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer fixture.Close()
	f := fixtureFetcher(t, fixture.URL, "/safe")
	f.interval = time.Hour
	if _, err := f.getObservation(context.Background(), fixture.URL+"/safe"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.getObservation(ctx, fixture.URL+"/safe"); err == nil {
		t.Fatal("cancelled request accepted")
	}
}

func TestFixtureGetRecordedSeparatesRawEvidence(t *testing.T) {
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=private")
		io.WriteString(w, "private@example.com")
	}))
	defer fixture.Close()
	path := filepath.Join(t.TempDir(), "shadow.db")
	st, err := store.OpenWithEvidenceKey(path, bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	scope, _ := policy.FromTarget(fixture.URL)
	read := policy.ActionRule{URL: fixture.URL + "/safe?token=private", Method: http.MethodGet, Effect: policy.EffectRead}
	if err := st.StartRun(ctx, "run-1", scope, []policy.ActionRule{read}); err != nil {
		t.Fatal(err)
	}
	d, err := newFixtureDispatcher(ctx, st, "run-1", []policy.ActionRule{read}, Options{AllowLoopback: true, interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	obs, id, err := d.getRecorded(ctx, http.MethodGet, read.URL)
	if err != nil || id <= 0 || obs.Status != 200 {
		t.Fatalf("recorded fetch: %#v %d %v", obs, id, err)
	}
	events, err := st.Events(context.Background(), "run-1")
	if err != nil || len(events) != 3 || events[1].Kind != "network_decision" || bytes.Contains(events[2].Payload, []byte("private")) {
		t.Fatalf("minimized event: %#v %v", events, err)
	}
	raw, err := st.RawEvidence(context.Background(), "run-1", id)
	if err != nil {
		t.Fatal(err)
	}
	var response store.RawHTTP
	if err := json.Unmarshal(raw, &response); err != nil || string(response.Body) != "private@example.com" || response.Header.Get("Set-Cookie") != "session=private" {
		t.Fatalf("raw evidence mismatch: %#v %v", response, err)
	}
	withoutKey, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer withoutKey.Close()
	if _, err := withoutKey.RawEvidence(context.Background(), "run-1", id); err == nil {
		t.Fatal("evidence read without key succeeded")
	}
}

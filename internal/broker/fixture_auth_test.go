package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	keyring "github.com/zalando/go-keyring"
	"shadow/internal/config"
	"shadow/internal/policy"
	"shadow/internal/store"
)

func authFixtureRun(t *testing.T, server *httptest.Server, runID string, st *store.Store) (*FixtureRunNetwork, policy.ActionRule, policy.ActionRule) {
	t.Helper()
	auth := policy.ActionRule{URL: server.URL + "/login", Method: http.MethodPost, Effect: policy.EffectAuth}
	read := policy.ActionRule{URL: server.URL + "/private", Method: http.MethodGet, Effect: policy.EffectRead}
	rules := []policy.ActionRule{auth, read}
	scope, _ := policy.FromTarget(server.URL)
	if err := st.StartRun(context.Background(), runID, scope, rules); err != nil {
		t.Fatal(err)
	}
	net, err := NewFixtureRunNetwork(context.Background(), st, runID, rules, Options{AllowLoopback: true, interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return net, auth, read
}

func setAuthCredential(t *testing.T, st *store.Store, runID, origin, actionID, secret string) {
	t.Helper()
	snapshot, err := st.RunSnapshot(context.Background(), runID)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.SetFixtureCredential(runID, origin, actionID, snapshot.CreatedAt.Format(time.RFC3339Nano), secret); err != nil {
		t.Fatal(err)
	}
}

func TestFixtureAuthenticationSessionIsRunBoundAndVolatile(t *testing.T) {
	keyring.MockInit()
	ctx := context.Background()
	const secret = "private-login-password-927"
	const token = "private-cookie-token-371"
	var logins, authenticatedReads, ordinaryReads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			logins.Add(1)
			var body struct {
				Credential string `json:"credential"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Credential != secret {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Set-Cookie", "shadow_fixture_session="+token+"; Path=/; HttpOnly; SameSite=Strict; Max-Age=2")
			w.WriteHeader(http.StatusNoContent)
		case "/private":
			if c, err := r.Cookie("shadow_fixture_session"); err == nil && c.Value == token {
				authenticatedReads.Add(1)
				w.Write([]byte("private response"))
			} else {
				ordinaryReads.Add(1)
				w.WriteHeader(http.StatusUnauthorized)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "shadow.db")
	st, err := store.OpenWithEvidenceKey(path, bytes.Repeat([]byte{0x19}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	network, auth, read := authFixtureRun(t, server, "run-1", st)
	authID, readID := FixtureAuthActionID(auth), ReadActionID(read)
	if err := network.Authenticate(ctx, authID); err == nil || logins.Load() != 0 {
		t.Fatalf("missing credential reached fixture: %v", err)
	}
	setAuthCredential(t, st, "run-1", server.URL, authID, "wrong")
	if err := network.Authenticate(ctx, authID); err == nil || logins.Load() != 1 {
		t.Fatalf("wrong credential established session: %v", err)
	}
	setAuthCredential(t, st, "run-1", server.URL, authID, secret)
	if err := network.Authenticate(ctx, authID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := network.ReadAuthenticated(ctx, authID, "unknown"); err == nil {
		t.Fatal("unknown read ID used session")
	}
	if got, _, err := network.ReadAuthenticated(ctx, authID, readID); err != nil || got.Status != 200 {
		t.Fatalf("authenticated read: %+v %v", got, err)
	}
	if got, _, err := network.ReadRecorded(ctx, readID); err != nil || got.Status != 401 {
		t.Fatalf("ordinary read inherited cookie: %+v %v", got, err)
	}
	other, _, _ := authFixtureRun(t, server, "run-2", st)
	if _, _, err := other.ReadAuthenticated(ctx, authID, readID); err == nil {
		t.Fatal("session crossed run")
	}
	if err := other.Authenticate(ctx, authID); err == nil {
		t.Fatal("credential crossed run")
	}
	restarted, err := NewFixtureRunNetwork(ctx, st, "run-1", []policy.ActionRule{auth, read}, Options{AllowLoopback: true, interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := restarted.ReadAuthenticated(ctx, authID, readID); err == nil {
		t.Fatal("session survived adapter restart")
	}
	if logins.Load() != 2 || authenticatedReads.Load() != 1 || ordinaryReads.Load() != 1 {
		t.Fatalf("unexpected requests: login=%d authenticated=%d ordinary=%d", logins.Load(), authenticatedReads.Load(), ordinaryReads.Load())
	}
	events, err := st.Events(ctx, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		for _, private := range []string{secret, token, "wrong", "/login", "/private"} {
			if strings.Contains(string(event.Payload), private) {
				t.Fatalf("event %d leaked private material", event.ID)
			}
		}
	}
	if err := st.PurgeRun(ctx, "run-1"); err != nil {
		t.Fatal(err)
	}
	if err := network.Authenticate(ctx, authID); err == nil || logins.Load() != 2 {
		t.Fatal("purged run retained authentication authority")
	}
	changed := read
	changed.URL = server.URL + "/changed"
	scope, _ := policy.FromTarget(server.URL)
	if err := st.StartRun(ctx, "run-1", scope, []policy.ActionRule{auth, changed}); err != nil {
		t.Fatal(err)
	}
	if err := network.Authenticate(ctx, authID); err == nil || logins.Load() != 2 {
		t.Fatal("changed run grants retained an old authentication adapter")
	}
	changedNetwork, err := NewFixtureRunNetwork(ctx, st, "run-1", []policy.ActionRule{auth, changed}, Options{AllowLoopback: true, interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := changedNetwork.Authenticate(ctx, authID); err == nil || logins.Load() != 2 {
		t.Fatal("new run reused purged run's credential")
	}
}

func TestFixtureAuthenticationRejectsCookieScopeRedirectAndTimeout(t *testing.T) {
	keyring.MockInit()
	for _, tc := range []struct {
		name, cookie string
		status       int
		wait         bool
	}{
		{"domain", "shadow_fixture_session=t; Domain=example.com; Path=/; HttpOnly; SameSite=Strict; Max-Age=5", 204, false},
		{"path", "shadow_fixture_session=t; Path=/private; HttpOnly; SameSite=Strict; Max-Age=5", 204, false},
		{"missing-http-only", "shadow_fixture_session=t; Path=/; SameSite=Strict; Max-Age=5", 204, false},
		{"too-long", "shadow_fixture_session=t; Path=/; HttpOnly; SameSite=Strict; Max-Age=9999", 204, false},
		{"secure-on-http", "shadow_fixture_session=t; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=5", 204, false},
		{"duplicate-age", "shadow_fixture_session=t; Path=/; HttpOnly; SameSite=Strict; Max-Age=5; Max-Age=500", 204, false},
		{"redirect", "", 302, false},
		{"timeout", "", 204, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logins, reads atomic.Int32
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/login" {
					logins.Add(1)
					if tc.wait {
						<-release
						return
					}
					if tc.status == 302 {
						w.Header().Set("Location", "/private")
					}
					if tc.cookie != "" {
						w.Header().Set("Set-Cookie", tc.cookie)
					}
					w.WriteHeader(tc.status)
					return
				}
				reads.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			st, err := store.OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), bytes.Repeat([]byte{0x23}, 32))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			network, auth, read := authFixtureRun(t, server, "run", st)
			authID := FixtureAuthActionID(auth)
			setAuthCredential(t, st, "run", server.URL, authID, "secret-192")
			ctx := context.Background()
			if tc.wait {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 30*time.Millisecond)
				defer cancel()
			}
			err = network.Authenticate(ctx, authID)
			close(release)
			if err == nil {
				t.Fatal("invalid authentication established a session")
			}
			if _, _, err := network.ReadAuthenticated(context.Background(), authID, ReadActionID(read)); err == nil {
				t.Fatal("failed login left a session")
			}
			if logins.Load() != 1 || reads.Load() != 0 {
				t.Fatalf("redirect/timeout escaped contract: logins=%d reads=%d", logins.Load(), reads.Load())
			}
		})
	}
}

func TestFixtureAuthenticationExpires(t *testing.T) {
	keyring.MockInit()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.Header().Set("Set-Cookie", "shadow_fixture_session=t; Path=/; HttpOnly; SameSite=Strict; Max-Age=1")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	st, err := store.OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), bytes.Repeat([]byte{0x24}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	network, auth, read := authFixtureRun(t, server, "run", st)
	authID := FixtureAuthActionID(auth)
	setAuthCredential(t, st, "run", server.URL, authID, "secret")
	if err := network.Authenticate(context.Background(), authID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, _, err := network.ReadAuthenticated(context.Background(), authID, ReadActionID(read)); err == nil {
		t.Fatal("expired cookie was sent")
	}
}

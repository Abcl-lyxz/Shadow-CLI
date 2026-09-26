package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"shadow/internal/policy"
	"shadow/internal/store"
)

func fixtureRecordRules(base string) (policy.ActionRule, policy.ActionRule) {
	write := policy.ActionRule{URL: base + "/records", Method: http.MethodPost, Effect: policy.EffectTestWrite, Resource: "shadow_record_1", CleanupURL: base + "/records/shadow_record_1", CleanupMethod: http.MethodDelete}
	return write, policy.ActionRule{URL: write.CleanupURL, Method: http.MethodGet, Effect: policy.EffectRead}
}

func TestFixtureRecordCleanupUnknownAndRestartInspection(t *testing.T) {
	ctx := context.Background()
	var present, ambiguous atomic.Bool
	var posts, deletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/records":
			posts.Add(1)
			var request struct {
				Resource string `json:"resource"`
			}
			if json.NewDecoder(r.Body).Decode(&request) != nil || request.Resource != "shadow_record_1" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			present.Store(true)
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodDelete && r.URL.Path == "/records/shadow_record_1":
			deletes.Add(1)
			present.Store(false)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/records/shadow_record_1":
			if present.Load() {
				fmt.Fprint(w, `{"record":{"id":"shadow_record_1","status":"active"}}`)
				return
			}
			w.WriteHeader(http.StatusGone)
			if ambiguous.Load() {
				fmt.Fprint(w, `{"record":{"id":"shadow_record_1","status":"unknown"}}`)
			} else {
				fmt.Fprint(w, `{"record":{"id":"shadow_record_1","status":"deleted"}}`)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "shadow.db")
	key := bytes.Repeat([]byte{0x61}, 32)
	st, err := store.OpenWithEvidenceKey(path, key)
	if err != nil {
		t.Fatal(err)
	}
	write, read := fixtureRecordRules(server.URL)
	rules := []policy.ActionRule{write, read}
	scope, _ := policy.FromTarget(server.URL)
	if err := st.StartRun(ctx, "run", scope, rules); err != nil {
		t.Fatal(err)
	}
	network, err := NewFixtureRunNetwork(ctx, st, "run", rules, Options{AllowLoopback: true, interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	id := FixtureWriteActionID(write)
	if _, _, err := network.WriteMarker(ctx, id); err == nil {
		t.Fatal("record action crossed marker adapter")
	}
	actionID, presenceID, err := network.WriteRecord(ctx, id)
	if err != nil || actionID == 0 || presenceID == 0 || posts.Load() != 1 {
		t.Fatalf("record write: action=%d presence=%d posts=%d err=%v", actionID, presenceID, posts.Load(), err)
	}
	actions, err := st.TestActions(ctx, "run")
	if err != nil || len(actions) != 1 || actions[0].CleanupProtocol != store.FixtureRecordProtocolV1 {
		t.Fatalf("record protocol not journaled: %+v %v", actions, err)
	}
	ambiguous.Store(true)
	if _, err := network.CleanupMarker(ctx, id, actionID, presenceID); err == nil {
		t.Fatal("record cleanup crossed marker adapter")
	}
	afterID, err := network.CleanupRecord(ctx, id, actionID, presenceID)
	if err == nil || afterID == 0 || deletes.Load() != 1 {
		t.Fatalf("ambiguous response resolved cleanup: after=%d deletes=%d err=%v", afterID, deletes.Load(), err)
	}
	if err := st.PurgeRun(ctx, "run"); err == nil {
		t.Fatal("unresolved record cleanup was purged")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = store.OpenWithEvidenceKey(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := NewFixtureRunNetwork(ctx, st, "run", rules, Options{AllowLoopback: false}); err == nil {
		t.Fatal("record adapter lost loopback restriction")
	}
	restarted, err := NewFixtureRunNetwork(ctx, st, "run", rules, Options{AllowLoopback: true, interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := restarted.WriteRecord(ctx, id); err == nil || posts.Load() != 1 {
		t.Fatal("restart replayed record POST")
	}
	if _, err := restarted.CleanupRecord(ctx, id, actionID, presenceID); err == nil || deletes.Load() != 1 {
		t.Fatal("restart replayed record DELETE")
	}
	ambiguous.Store(false)
	verifiedID, err := restarted.InspectCleanup(ctx, id, actionID, presenceID)
	if err != nil || verifiedID <= afterID || deletes.Load() != 1 {
		t.Fatalf("read-only recovery failed: id=%d err=%v deletes=%d", verifiedID, err, deletes.Load())
	}
	actions, err = st.TestActions(ctx, "run")
	if err != nil || actions[0].Status != store.TestActionFixtureVerified {
		t.Fatalf("record obligation not verified: %+v %v", actions, err)
	}
	if err := st.PurgeRun(ctx, "run"); err != nil {
		t.Fatal(err)
	}
}

func TestFixtureRecordRejectsFalseAbsenceAndWrongRoutes(t *testing.T) {
	write, read := fixtureRecordRules("http://127.0.0.1:8123")
	bad := write
	bad.CleanupURL += "?token=secret"
	if _, err := store.FixtureProtocolForRule(bad); err == nil {
		t.Fatal("record protocol accepted cleanup query")
	}
	bad = write
	bad.URL += "/other"
	if _, err := store.FixtureProtocolForRule(bad); err == nil {
		t.Fatal("record protocol accepted arbitrary POST route")
	}
	summary := store.EvidenceSummary{ContentType: "application/json", Status: 410}
	base := store.RawHTTP{RequestURL: read.URL, Method: http.MethodGet, Status: 410, Body: []byte(`{"record":{"id":"shadow_record_1","status":"deleted"}}`)}
	if !store.FixtureRecordState(summary, base, read.URL, write.Resource, false) {
		t.Fatal("valid absent state rejected")
	}
	for _, body := range []string{`{"record":{"id":"shadow_record_1","status":"active"}}`, `{"record":{"id":"other","status":"deleted"}}`, `{"record":{"id":"shadow_record_1","status":"deleted","extra":true}}`, `{"record":{"id":"shadow_record_1","status":"deleted"}} {}`} {
		bad := base
		bad.Body = []byte(body)
		if store.FixtureRecordState(summary, bad, read.URL, write.Resource, false) {
			t.Fatalf("false absence accepted: %s", body)
		}
	}
}

func TestFixtureRecordUnknownWriteRecoveredWithoutReplay(t *testing.T) {
	ctx := context.Background()
	var present atomic.Bool
	var posts, deletes atomic.Int32
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			posts.Add(1)
			present.Store(true)
			<-release
			w.WriteHeader(http.StatusCreated)
		case http.MethodDelete:
			deletes.Add(1)
			present.Store(false)
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			if present.Load() {
				fmt.Fprint(w, `{"record":{"id":"shadow_record_1","status":"active"}}`)
			} else {
				w.WriteHeader(http.StatusGone)
				fmt.Fprint(w, `{"record":{"id":"shadow_record_1","status":"deleted"}}`)
			}
		}
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "shadow.db")
	key := bytes.Repeat([]byte{0x62}, 32)
	st, err := store.OpenWithEvidenceKey(path, key)
	if err != nil {
		t.Fatal(err)
	}
	write, read := fixtureRecordRules(server.URL)
	rules := []policy.ActionRule{write, read}
	scope, _ := policy.FromTarget(server.URL)
	if err := st.StartRun(ctx, "run", scope, rules); err != nil {
		t.Fatal(err)
	}
	network, err := NewFixtureRunNetwork(ctx, st, "run", rules, Options{AllowLoopback: true, interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	id := FixtureWriteActionID(write)
	deadline, cancel := context.WithTimeout(ctx, 40*time.Millisecond)
	actionID, presenceID, err := network.WriteRecord(deadline, id)
	cancel()
	close(release)
	if err == nil || actionID == 0 || presenceID != 0 || posts.Load() != 1 {
		t.Fatalf("write uncertainty not journaled: action=%d presence=%d posts=%d err=%v", actionID, presenceID, posts.Load(), err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = store.OpenWithEvidenceKey(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	restarted, err := NewFixtureRunNetwork(ctx, st, "run", rules, Options{AllowLoopback: true, interval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := restarted.WriteRecord(ctx, id); err == nil || posts.Load() != 1 {
		t.Fatal("unknown POST replayed after restart")
	}
	presenceID, err = restarted.InspectWrite(ctx, id, actionID)
	if err != nil || presenceID == 0 {
		t.Fatalf("unknown write not inspected: id=%d err=%v", presenceID, err)
	}
	if _, err := restarted.CleanupRecord(ctx, id, actionID, presenceID); err != nil || deletes.Load() != 1 {
		t.Fatalf("record cleanup after unknown write: deletes=%d err=%v", deletes.Load(), err)
	}
}

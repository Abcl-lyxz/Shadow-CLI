package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

func TestApprovedReadBindsLocalApprovalAndRecordedEvidence(t *testing.T) {
	ctx := context.Background()
	var st *store.Store
	var hits, escaped atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { escaped.Add(1) }))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		events, err := st.Events(ctx, "approved")
		if err != nil || len(events) < 2 || events[len(events)-1].Kind != "network_decision" {
			t.Errorf("request arrived before a durable decision: %v", err)
		}
		switch r.URL.Path {
		case "/safe":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "secret=response")
		case "/redirect":
			http.Redirect(w, r, other.URL+"/escape", http.StatusFound)
		case "/same-origin-redirect":
			http.Redirect(w, r, "/unlisted", http.StatusFound)
		default:
			t.Errorf("unlisted route reached target: %s", r.URL)
		}
	}))
	defer server.Close()
	var err error
	st, err = store.OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), bytes.Repeat([]byte{0x43}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rules := policy.TrustedRules{Version: 1, Origin: server.URL, Actions: []policy.ActionRule{
		{URL: server.URL + "/safe", Method: http.MethodGet, Effect: policy.EffectRead},
		{URL: server.URL + "/redirect", Method: http.MethodGet, Effect: policy.EffectRead},
		{URL: server.URL + "/same-origin-redirect", Method: http.MethodGet, Effect: policy.EffectRead},
	}}
	key := bytes.Repeat([]byte{0x51}, 32)
	now := time.Now().UTC().Truncate(time.Second)
	approval, err := policy.SignRuleApproval(rules, key, now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := policy.VerifyApprovedRules(rules, approval, key, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.StartApprovedRun(ctx, "approved", verified); err != nil {
		t.Fatal(err)
	}
	if _, err := NewApprovedReadNetwork(ctx, st, "approved", verified); err == nil {
		t.Fatal("public constructor accepted a loopback destination")
	}
	if _, err := newApprovedReadNetwork(ctx, st, "approved", verified, Options{
		lookup: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("169.254.169.254")}, nil
		},
	}, true); err == nil {
		t.Fatal("mixed DNS answer accepted a blocked destination")
	}
	n, err := newApprovedReadNetwork(ctx, st, "approved", verified, Options{allowedURLs: []string{server.URL + "/unlisted"}, interval: time.Millisecond}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := n.ReadRecorded(ctx, ReadActionID(policy.ActionRule{URL: server.URL + "/unlisted", Method: http.MethodGet, Effect: policy.EffectRead})); err == nil || hits.Load() != 0 {
		t.Fatalf("caller URL list expanded grant: %v hits=%d", err, hits.Load())
	}
	obs, eventID, err := n.ReadRecorded(ctx, ReadActionID(rules.Actions[0]))
	if err != nil || eventID <= 0 || obs.Status != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("approved read: %#v %d %v", obs, eventID, err)
	}
	events, err := st.Events(ctx, "approved")
	if err != nil || len(events) != 3 || bytes.Contains(events[2].Payload, []byte("secret=response")) {
		t.Fatalf("raw response reached event log: %v %v", events, err)
	}
	raw, err := st.RawEvidence(ctx, "approved", eventID)
	if err != nil {
		t.Fatal(err)
	}
	var decoded store.RawHTTP
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded.RequestURL != rules.Actions[0].URL || string(decoded.Body) != "secret=response" {
		t.Fatalf("evidence route: %#v %v", decoded, err)
	}
	if _, _, err := n.ReadRecorded(ctx, ReadActionID(rules.Actions[1])); err == nil || escaped.Load() != 0 {
		t.Fatalf("redirect escaped exact origin: %v hits=%d", err, escaped.Load())
	}
	if _, _, err := n.ReadRecorded(ctx, ReadActionID(rules.Actions[2])); err == nil || hits.Load() != 3 {
		t.Fatalf("same-origin redirect reached an unlisted route: %v hits=%d", err, hits.Load())
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := n.ReadRecorded(cancelled, ReadActionID(rules.Actions[0])); err == nil || hits.Load() != 3 {
		t.Fatalf("cancelled request reached target: %v hits=%d", err, hits.Load())
	}
	for i := 0; i < 13; i++ {
		token, err := st.ReserveFixtureRequest(ctx, "approved", false, time.Nanosecond)
		if err != nil {
			t.Fatalf("fill shared run budget %d: %v", i, err)
		}
		if err := st.ReleaseFixtureRequest(ctx, "approved", token); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := n.ReadRecorded(ctx, ReadActionID(rules.Actions[0])); err == nil || hits.Load() != 3 {
		t.Fatalf("exhausted run budget reached target: %v hits=%d", err, hits.Load())
	}
	if err := st.PurgeRun(ctx, "approved"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := n.ReadRecorded(ctx, ReadActionID(rules.Actions[0])); err == nil || hits.Load() != 3 {
		t.Fatalf("purged approval retained network access: %v hits=%d", err, hits.Load())
	}
}

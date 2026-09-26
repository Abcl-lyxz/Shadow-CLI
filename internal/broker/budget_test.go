package broker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"shadow/internal/policy"
	"shadow/internal/store"
)

func TestFixtureDispatchersShareDurableRunBudget(t *testing.T) {
	var hits atomic.Int32
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("ok"))
	}))
	defer fixture.Close()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "shadow.db")
	key := bytes.Repeat([]byte{0x31}, 32)
	st, err := store.OpenWithEvidenceKey(path, key)
	if err != nil {
		t.Fatal(err)
	}
	scope, _ := policy.FromTarget(fixture.URL)
	rule := policy.ActionRule{URL: fixture.URL + "/safe", Method: http.MethodGet, Effect: policy.EffectRead}
	if err := st.StartRun(ctx, "run-1", scope, []policy.ActionRule{rule}); err != nil {
		t.Fatal(err)
	}
	opts := Options{AllowLoopback: true, interval: time.Millisecond}
	first, err := newFixtureDispatcher(ctx, st, "run-1", []policy.ActionRule{rule}, opts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newFixtureDispatcher(ctx, st, "run-1", []policy.ActionRule{rule}, opts)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 16; i++ {
		dispatcher := first
		if i%2 == 1 {
			dispatcher = second
		}
		if _, _, err := dispatcher.getRecorded(ctx, http.MethodGet, rule.URL); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := store.OpenWithEvidenceKey(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	third, err := newFixtureDispatcher(ctx, reopened, "run-1", []policy.ActionRule{rule}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := third.getRecorded(ctx, http.MethodGet, rule.URL); err == nil || hits.Load() != 16 {
		t.Fatalf("new dispatcher bypassed the durable budget: err=%v hits=%d", err, hits.Load())
	}
}

func TestFixtureDispatchersShareInFlightLease(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var hits atomic.Int32
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			close(started)
			<-release
		}
		w.Write([]byte("ok"))
	}))
	defer fixture.Close()
	ctx := context.Background()
	st, err := store.OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), bytes.Repeat([]byte{0x32}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	scope, _ := policy.FromTarget(fixture.URL)
	rule := policy.ActionRule{URL: fixture.URL + "/safe", Method: http.MethodGet, Effect: policy.EffectRead}
	if err := st.StartRun(ctx, "run-1", scope, []policy.ActionRule{rule}); err != nil {
		t.Fatal(err)
	}
	opts := Options{AllowLoopback: true, interval: time.Millisecond}
	first, err := newFixtureDispatcher(ctx, st, "run-1", []policy.ActionRule{rule}, opts)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newFixtureDispatcher(ctx, st, "run-1", []policy.ActionRule{rule}, opts)
	if err != nil {
		t.Fatal(err)
	}
	firstResult := make(chan error, 1)
	go func() {
		_, _, err := first.getRecorded(ctx, http.MethodGet, rule.URL)
		firstResult <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first request did not reach fixture")
	}
	if err := st.PurgeRun(ctx, "run-1"); err == nil {
		t.Fatal("purged a run while its network request was in flight")
	}
	waitCtx, cancel := context.WithTimeout(ctx, 40*time.Millisecond)
	defer cancel()
	if _, _, err := second.getRecorded(waitCtx, http.MethodGet, rule.URL); !errors.Is(err, context.DeadlineExceeded) || hits.Load() != 1 {
		t.Fatalf("second dispatcher overlapped the first: err=%v hits=%d", err, hits.Load())
	}
	unblock()
	if err := <-firstResult; err != nil {
		t.Fatal(err)
	}
	if err := st.PurgeRun(ctx, "run-1"); err != nil {
		t.Fatalf("completed request still blocked purge: %v", err)
	}
}

func TestFixtureCleanupKeepsReservedRequestsAfterReadBudgetEnds(t *testing.T) {
	var present atomic.Bool
	var deletes atomic.Int32
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			if !present.Load() {
				w.WriteHeader(http.StatusNotFound)
			}
			fmt.Fprintf(w, `{"resource":"shadow_marker_1","present":%t}`, present.Load())
		case http.MethodPost:
			present.Store(true)
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"created":true}`))
		case http.MethodDelete:
			deletes.Add(1)
			present.Store(false)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer fixture.Close()
	st, write, read := fixtureWriteStore(t, filepath.Join(t.TempDir(), "shadow.db"), fixture.URL, bytes.Repeat([]byte{0x33}, 32))
	defer st.Close()
	ctx := context.Background()
	opts := Options{AllowLoopback: true, interval: time.Millisecond}
	writer, err := newFixtureWriteDispatcher(ctx, st, "run", write, read, opts)
	if err != nil {
		t.Fatal(err)
	}
	actionID, presenceID, err := writer.Dispatch(ctx)
	if err != nil || actionID <= 0 || presenceID <= 0 {
		t.Fatalf("fixture write did not reach presence evidence: %d %d %v", actionID, presenceID, err)
	}
	reader, err := newFixtureDispatcher(ctx, st, "run", []policy.ActionRule{read}, opts)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 13; i++ {
		if _, _, err := reader.getRecorded(ctx, http.MethodGet, read.URL); err != nil {
			t.Fatalf("ordinary read %d: %v", i, err)
		}
	}
	if _, _, err := reader.getRecorded(ctx, http.MethodGet, read.URL); err == nil {
		t.Fatal("ordinary read exceeded its lane")
	}
	cleanup, err := newFixtureCleanupExecutor(ctx, st, "run", write, read, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cleanup.Cleanup(ctx, actionID, presenceID); err != nil || deletes.Load() != 1 || present.Load() {
		t.Fatalf("reserved cleanup failed: deletes=%d present=%t err=%v", deletes.Load(), present.Load(), err)
	}
}

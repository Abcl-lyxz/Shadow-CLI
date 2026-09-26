package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"reflect"

	"shadow/internal/policy"
	"shadow/internal/store"
)

// FixtureCleanupExecutor is a loopback-only recovery slice. It can DELETE one
// exact, trusted cleanup route for an already journaled possible test write.
// It never creates a resource and is not exposed to agent tools.
type FixtureCleanupExecutor struct {
	store    *store.Store
	runID    string
	snapshot store.RunSnapshot
	write    policy.ActionRule
	read     policy.ActionRule
	reader   *FixtureDispatcher
	cleanup  *Fetcher
}

type cleanupActionContextKey struct{}

func NewFixtureCleanupExecutor(ctx context.Context, st *store.Store, runID string, write, read policy.ActionRule, opts Options) (*FixtureCleanupExecutor, error) {
	if st == nil || runID == "" || !opts.AllowLoopback || write.Effect != policy.EffectTestWrite || read.Effect != policy.EffectRead || read.Method != http.MethodGet || read.URL != write.CleanupURL {
		return nil, errors.New("fixture cleanup requires an explicit loopback write and read contract")
	}
	snapshot, err := st.RunSnapshot(ctx, runID)
	if err != nil || snapshot.RunID != runID || !snapshot.AllowsAction(write) || !snapshot.AllowsAction(read) {
		return nil, errors.New("fixture cleanup rules are not in the run snapshot")
	}
	scope, err := policy.FromTarget(snapshot.Origin)
	if err != nil || scope.Origin != snapshot.Origin {
		return nil, errors.New("invalid fixture cleanup run scope")
	}
	if _, err := policy.NewActionPolicy(scope, []policy.ActionRule{write, read}); err != nil {
		return nil, err
	}
	reader, err := NewFixtureDispatcher(ctx, st, runID, []policy.ActionRule{read}, opts)
	if err != nil {
		return nil, err
	}
	opts.AllowedURLs = []string{write.CleanupURL}
	cleanup, err := New(ctx, scope, opts)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(cleanup.IP()); ip == nil || !ip.IsLoopback() || !ip.Equal(net.ParseIP(reader.fetcher.IP())) {
		return nil, errors.New("fixture cleanup destination differs from read destination")
	}
	cleanup.cleanupOnly = true
	e := &FixtureCleanupExecutor{store: st, runID: runID, snapshot: snapshot, write: write, read: read, reader: reader, cleanup: cleanup}
	cleanup.guard = e.authorizeCleanup
	return e, nil
}

func (e *FixtureCleanupExecutor) action(ctx context.Context, actionID int64) (store.TestAction, error) {
	if e == nil || e.store == nil || actionID <= 0 {
		return store.TestAction{}, errors.New("fixture cleanup unavailable")
	}
	current, err := e.store.RunSnapshot(ctx, e.runID)
	if err != nil || !reflect.DeepEqual(current, e.snapshot) {
		return store.TestAction{}, errors.New("fixture run snapshot is unavailable or changed")
	}
	actions, err := e.store.TestActions(ctx, e.runID)
	if err != nil {
		return store.TestAction{}, err
	}
	for _, action := range actions {
		if action.ID == actionID && action.Origin == current.Origin && action.Resource == e.write.Resource && action.Method == e.write.Method && action.URLSHA256 == routeDigest(e.write.URL) && action.CleanupMethod == http.MethodDelete && action.CleanupURLSHA256 == routeDigest(e.write.CleanupURL) {
			return action, nil
		}
	}
	return store.TestAction{}, errors.New("fixture cleanup action does not match the trusted plan")
}

func routeDigest(raw string) string {
	digest := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(digest[:])
}

func (e *FixtureCleanupExecutor) authorizeCleanup(ctx context.Context, raw string) error {
	if raw != e.write.CleanupURL || e.cleanup == nil {
		return errors.New("fixture cleanup route denied")
	}
	actionID, ok := ctx.Value(cleanupActionContextKey{}).(int64)
	if !ok {
		return errors.New("fixture cleanup action is unbound")
	}
	current, err := e.store.RunSnapshot(ctx, e.runID)
	if err != nil || !reflect.DeepEqual(current, e.snapshot) {
		return errors.New("fixture cleanup run snapshot is unavailable or changed")
	}
	action, err := e.action(ctx, actionID)
	if err != nil || action.Status != store.TestActionCleanupAttempted {
		return errors.New("fixture cleanup attempt is not journaled")
	}
	return nil
}

// Cleanup requires a recorded GET showing the named fixture marker present
// after the possible write. It journals the DELETE attempt before dispatch,
// records an authenticated GET afterward, and verifies the fixture's exact
// present/absent response contract. Interrupted attempts stay visible and are
// never replayed automatically.
func (e *FixtureCleanupExecutor) Cleanup(ctx context.Context, actionID, presenceEventID int64) (int64, error) {
	action, err := e.action(ctx, actionID)
	if err != nil || action.Status != store.TestActionWritePossible || presenceEventID <= action.WriteEventID {
		return 0, errors.New("fixture cleanup requires a possible write and later presence evidence")
	}
	before, raw, err := e.store.ValidatedObservation(ctx, e.runID, presenceEventID)
	if err != nil || !store.FixtureMarkerState(before, raw, e.read.URL, e.write.Resource, true) {
		return 0, errors.New("fixture presence evidence is invalid")
	}
	if err := e.store.MarkCleanupAttempted(ctx, e.runID, actionID); err != nil {
		return 0, err
	}
	action, err = e.action(ctx, actionID)
	if err != nil || action.Status != store.TestActionCleanupAttempted {
		return 0, errors.New("fixture cleanup attempt is not journaled")
	}
	deleted, err := e.cleanup.delete(context.WithValue(ctx, cleanupActionContextKey{}, actionID), e.write.CleanupURL)
	if err != nil || deleted.Status < 200 || deleted.Status > 299 {
		return 0, errors.New("fixture DELETE result is unknown or unsuccessful; inspect the cleanup journal")
	}
	_, afterID, err := e.reader.GetRecorded(ctx, http.MethodGet, e.read.URL)
	if err != nil {
		return 0, errors.New("fixture cleanup read failed; inspect the cleanup journal")
	}
	if err := e.store.RecordCleanupObservation(ctx, e.runID, actionID, afterID); err != nil {
		return afterID, err
	}
	if err := e.store.VerifyFixtureCleanup(ctx, e.runID, actionID, presenceEventID, e.read.URL); err != nil {
		return afterID, err
	}
	return afterID, nil
}

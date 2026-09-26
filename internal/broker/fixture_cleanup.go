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

// fixtureCleanupExecutor is a loopback-only recovery slice. It can DELETE one
// exact, trusted cleanup route for an already journaled possible test write.
// It never creates a resource and is not exposed to agent tools.
type fixtureCleanupExecutor struct {
	store    *store.Store
	runID    string
	snapshot store.RunSnapshot
	write    policy.ActionRule
	read     policy.ActionRule
	protocol cleanupProtocol
	reader   *fixtureDispatcher
	cleanup  *fetcher
}

type cleanupActionContextKey struct{}

func newFixtureCleanupExecutor(ctx context.Context, st *store.Store, runID string, write, read policy.ActionRule, opts Options) (*fixtureCleanupExecutor, error) {
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
	protocol, err := newFixtureProtocol(write, read)
	if err != nil {
		return nil, err
	}
	reader, err := newFixtureDispatcher(ctx, st, runID, []policy.ActionRule{read}, opts)
	if err != nil {
		return nil, err
	}
	opts.allowedURLs = []string{write.CleanupURL}
	cleanup, err := newFetcher(ctx, scope, opts)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(cleanup.ipString()); ip == nil || !ip.IsLoopback() || !ip.Equal(net.ParseIP(reader.fetcher.ipString())) {
		return nil, errors.New("fixture cleanup destination differs from read destination")
	}
	cleanup.cleanupOnly = true
	bindFixtureBudget(reader.fetcher, st, runID, true)
	bindFixtureBudget(cleanup, st, runID, true)
	e := &fixtureCleanupExecutor{store: st, runID: runID, snapshot: snapshot, write: write, read: read, protocol: protocol, reader: reader, cleanup: cleanup}
	cleanup.guard = e.authorizeCleanup
	cleanup.deny = e.recordDenied
	return e, nil
}

func (e *fixtureCleanupExecutor) recordDenied(ctx context.Context, raw string) error {
	current, err := e.store.RunSnapshot(ctx, e.runID)
	if err != nil || !reflect.DeepEqual(current, e.snapshot) {
		return errors.New("fixture cleanup run snapshot is unavailable or changed")
	}
	return e.store.RecordFixtureNetworkDecision(ctx, current, http.MethodDelete, raw, false)
}

func (e *fixtureCleanupExecutor) action(ctx context.Context, actionID int64) (store.TestAction, error) {
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
		if action.ID == actionID && action.Origin == current.Origin && action.Resource == e.write.Resource && action.Method == e.write.Method && action.URLSHA256 == routeDigest(e.write.URL) && action.CleanupMethod == http.MethodDelete && action.CleanupURLSHA256 == routeDigest(e.write.CleanupURL) && action.FixtureCleanupCompatible(e.protocol.id()) {
			return action, nil
		}
	}
	return store.TestAction{}, errors.New("fixture cleanup action does not match the trusted plan")
}

func routeDigest(raw string) string {
	digest := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(digest[:])
}

func (e *fixtureCleanupExecutor) authorizeCleanup(ctx context.Context, raw string) error {
	if e == nil || e.cleanup == nil {
		return errors.New("fixture cleanup unavailable")
	}
	deny := func(reason string) error {
		if err := e.recordDenied(ctx, raw); err != nil {
			return err
		}
		return errors.New(reason)
	}
	if raw != e.write.CleanupURL {
		return deny("fixture cleanup route denied")
	}
	actionID, ok := ctx.Value(cleanupActionContextKey{}).(int64)
	if !ok {
		return deny("fixture cleanup action is unbound")
	}
	current, err := e.store.RunSnapshot(ctx, e.runID)
	if err != nil || !reflect.DeepEqual(current, e.snapshot) {
		return errors.New("fixture cleanup run snapshot is unavailable or changed")
	}
	action, err := e.action(ctx, actionID)
	if err != nil || action.Status != store.TestActionCleanupAttempted {
		return deny("fixture cleanup attempt is not journaled")
	}
	return e.store.RecordFixtureMutationDecision(ctx, e.snapshot, http.MethodDelete, raw, actionID)
}

// InspectWrite records a fresh read after a possible write. It can recover
// presence evidence after a restart without repeating the POST.
func (e *fixtureCleanupExecutor) InspectWrite(ctx context.Context, actionID int64) (int64, error) {
	action, err := e.action(ctx, actionID)
	if err != nil || action.Status != store.TestActionWritePossible {
		return 0, errors.New("fixture write has no inspectable obligation")
	}
	_, eventID, err := e.reader.getRecorded(ctx, http.MethodGet, e.read.URL)
	if err != nil {
		return 0, err
	}
	summary, raw, err := e.store.ValidatedObservation(ctx, e.runID, eventID)
	if err != nil || eventID <= action.WriteEventID || e.protocol.inspect(summary, raw) != cleanupPresent {
		return eventID, errors.New("fixture marker presence was not verified")
	}
	return eventID, nil
}

// InspectCleanup reads an interrupted DELETE's outcome without replaying it.
// Absence can verify the fixture contract; presence leaves a review obligation.
func (e *fixtureCleanupExecutor) InspectCleanup(ctx context.Context, actionID, presenceEventID int64) (int64, error) {
	action, err := e.action(ctx, actionID)
	if err != nil || (action.Status != store.TestActionCleanupAttempted && action.Status != store.TestActionCleanupObserved) || !(action.WriteEventID < presenceEventID && presenceEventID < action.CleanupEventID) {
		return 0, errors.New("fixture cleanup has no inspectable attempt and presence evidence")
	}
	before, raw, err := e.store.ValidatedObservation(ctx, e.runID, presenceEventID)
	if err != nil || e.protocol.inspect(before, raw) != cleanupPresent {
		return 0, errors.New("fixture presence evidence is invalid")
	}
	_, afterID, err := e.reader.getRecorded(ctx, http.MethodGet, e.read.URL)
	if err != nil {
		return 0, err
	}
	if action.Status == store.TestActionCleanupObserved {
		err = e.store.ReinspectFixtureCleanup(ctx, e.runID, actionID, afterID)
	} else {
		err = e.store.RecordCleanupObservation(ctx, e.runID, actionID, afterID)
	}
	if err != nil {
		return afterID, err
	}
	if err := e.protocol.verify(ctx, e.store, e.runID, actionID, presenceEventID); err != nil {
		return afterID, err
	}
	return afterID, nil
}

// Cleanup requires a recorded GET showing the named fixture marker present
// after the possible write. It journals the DELETE attempt before dispatch,
// records an authenticated GET afterward, and verifies the fixture's exact
// present/absent response contract. Interrupted attempts stay visible and are
// never replayed automatically.
func (e *fixtureCleanupExecutor) Cleanup(ctx context.Context, actionID, presenceEventID int64) (int64, error) {
	action, err := e.action(ctx, actionID)
	if err != nil || action.Status != store.TestActionWritePossible || presenceEventID <= action.WriteEventID {
		return 0, errors.New("fixture cleanup requires a possible write and later presence evidence")
	}
	before, raw, err := e.store.ValidatedObservation(ctx, e.runID, presenceEventID)
	if err != nil || e.protocol.inspect(before, raw) != cleanupPresent {
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
	_, afterID, err := e.reader.getRecorded(ctx, http.MethodGet, e.read.URL)
	if err != nil {
		return 0, errors.New("fixture cleanup read failed; inspect the cleanup journal")
	}
	if err := e.store.RecordCleanupObservation(ctx, e.runID, actionID, afterID); err != nil {
		return afterID, err
	}
	if err := e.protocol.verify(ctx, e.store, e.runID, actionID, presenceEventID); err != nil {
		return afterID, err
	}
	return afterID, nil
}

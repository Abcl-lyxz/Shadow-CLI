package broker

import (
	"context"
	"errors"
	"net"
	"net/http"
	"reflect"
	"sync"

	"shadow/internal/policy"
	"shadow/internal/store"
)

// fixtureWriteDispatcher creates only a named marker in a loopback fixture.
// It has no agent or CLI entry point and cannot send caller-supplied payloads.
type fixtureWriteDispatcher struct {
	store    *store.Store
	runID    string
	snapshot store.RunSnapshot
	write    policy.ActionRule
	read     policy.ActionRule
	protocol cleanupProtocol
	actions  *policy.ActionPolicy
	reader   *fixtureDispatcher
	writer   *fetcher
	mu       sync.Mutex
	claimed  map[int64]bool
}

type writeActionContextKey struct{}

func newFixtureWriteDispatcher(ctx context.Context, st *store.Store, runID string, write, read policy.ActionRule, opts Options) (*fixtureWriteDispatcher, error) {
	if st == nil || runID == "" || !opts.AllowLoopback || write.Effect != policy.EffectTestWrite || write.Method != http.MethodPost || read.Effect != policy.EffectRead || read.Method != http.MethodGet || read.URL != write.CleanupURL {
		return nil, errors.New("fixture write requires an exact POST marker and GET cleanup contract")
	}
	snapshot, err := st.RunSnapshot(ctx, runID)
	if err != nil || snapshot.RunID != runID || !snapshot.AllowsAction(write) || !snapshot.AllowsAction(read) {
		return nil, errors.New("fixture write rules are not in the run snapshot")
	}
	scope, err := policy.FromTarget(snapshot.Origin)
	if err != nil || scope.Origin != snapshot.Origin {
		return nil, errors.New("invalid fixture write run scope")
	}
	actions, err := policy.NewActionPolicy(scope, []policy.ActionRule{write, read})
	if err != nil {
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
	// The write fetcher derives its sole destination from the trusted rule.
	opts.allowedURLs = []string{write.URL}
	writer, err := newFetcher(ctx, scope, opts)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(writer.ipString()); ip == nil || !ip.IsLoopback() || !ip.Equal(net.ParseIP(reader.fetcher.ipString())) {
		return nil, errors.New("fixture write destination differs from read destination")
	}
	writer.writeOnly = true
	bindFixtureBudget(writer, st, runID, false)
	d := &fixtureWriteDispatcher{store: st, runID: runID, snapshot: snapshot, write: write, read: read, protocol: protocol, actions: actions, reader: reader, writer: writer, claimed: make(map[int64]bool)}
	writer.guard = d.authorizeWrite
	writer.deny = d.recordDenied
	return d, nil
}

func (d *fixtureWriteDispatcher) recordDenied(ctx context.Context, raw string) error {
	current, err := d.store.RunSnapshot(ctx, d.runID)
	if err != nil || !reflect.DeepEqual(current, d.snapshot) {
		return errors.New("fixture write run snapshot is unavailable or changed")
	}
	return d.store.RecordFixtureNetworkDecision(ctx, current, http.MethodPost, raw, false)
}

func (d *fixtureWriteDispatcher) action(ctx context.Context, actionID int64) (store.TestAction, error) {
	if d == nil || d.store == nil || actionID <= 0 {
		return store.TestAction{}, errors.New("fixture write unavailable")
	}
	current, err := d.store.RunSnapshot(ctx, d.runID)
	if err != nil || !reflect.DeepEqual(current, d.snapshot) {
		return store.TestAction{}, errors.New("fixture run snapshot is unavailable or changed")
	}
	actions, err := d.store.TestActions(ctx, d.runID)
	if err != nil {
		return store.TestAction{}, err
	}
	for _, action := range actions {
		if action.ID == actionID && action.Origin == current.Origin && action.Resource == d.write.Resource && action.Method == d.write.Method && action.URLSHA256 == routeDigest(d.write.URL) && action.CleanupMethod == d.write.CleanupMethod && action.CleanupURLSHA256 == routeDigest(d.write.CleanupURL) && action.CleanupProtocol == d.protocol.id() {
			return action, nil
		}
	}
	return store.TestAction{}, errors.New("fixture write action does not match the trusted plan")
}

func (d *fixtureWriteDispatcher) authorizeWrite(ctx context.Context, raw string) error {
	if d == nil || d.writer == nil {
		return errors.New("fixture write unavailable")
	}
	deny := func(reason string) error {
		if err := d.recordDenied(ctx, raw); err != nil {
			return err
		}
		return errors.New(reason)
	}
	if raw != d.write.URL {
		return deny("fixture write route denied")
	}
	actionID, ok := ctx.Value(writeActionContextKey{}).(int64)
	if !ok || !d.actions.Classify(http.MethodPost, raw).Allowed {
		return deny("fixture write is unbound or denied")
	}
	action, err := d.action(ctx, actionID)
	if err != nil || action.Status != store.TestActionWritePossible {
		return deny("fixture write is not journaled as possible")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.claimed[actionID] {
		return deny("fixture write dispatch already claimed")
	}
	if err := d.store.RecordFixtureMutationDecision(ctx, d.snapshot, http.MethodPost, raw, actionID); err != nil {
		return err
	}
	d.claimed[actionID] = true
	return nil
}

// Dispatch records an absent marker before planning, commits the possible-write
// obligation before POST, then records a GET proving whether it appeared. A
// failed or interrupted request leaves its obligation in the journal.
func (d *fixtureWriteDispatcher) Dispatch(ctx context.Context) (int64, int64, error) {
	if d == nil || d.store == nil || d.reader == nil || d.writer == nil {
		return 0, 0, errors.New("fixture write unavailable")
	}
	_, beforeID, err := d.reader.getRecorded(ctx, http.MethodGet, d.read.URL)
	if err != nil {
		return 0, 0, err
	}
	before, raw, err := d.store.ValidatedObservation(ctx, d.runID, beforeID)
	if err != nil || d.protocol.inspect(before, raw) != cleanupAbsent {
		return 0, 0, errors.New("fixture marker is not proven absent before write")
	}
	actionID, err := d.store.PlanFixtureTestWrite(ctx, d.runID, d.actions.Classify(d.write.Method, d.write.URL))
	if err != nil {
		return 0, 0, err
	}
	if err := d.store.MarkTestWritePossible(ctx, d.runID, actionID); err != nil {
		return actionID, 0, err
	}
	result, err := d.writer.postMarker(context.WithValue(ctx, writeActionContextKey{}, actionID), d.write.URL, d.write.Resource)
	if err != nil {
		return actionID, 0, err
	}
	if err := d.store.Append(ctx, d.runID, "fixture_write_response", map[string]any{"test_action_id": actionID, "status": result.Status, "url_sha256": result.URLSHA256, "body_sha256": result.SHA256}); err != nil {
		return actionID, 0, err
	}
	if result.Status < 200 || result.Status > 299 {
		return actionID, 0, errors.New("fixture POST did not succeed; inspect the test action")
	}
	_, presenceID, err := d.reader.getRecorded(ctx, http.MethodGet, d.read.URL)
	if err != nil {
		return actionID, 0, err
	}
	presence, raw, err := d.store.ValidatedObservation(ctx, d.runID, presenceID)
	if err != nil || d.protocol.inspect(presence, raw) != cleanupPresent {
		return actionID, presenceID, errors.New("fixture POST outcome lacks marker presence evidence")
	}
	return actionID, presenceID, nil
}

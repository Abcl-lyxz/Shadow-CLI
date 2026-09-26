package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"reflect"
	"sort"

	"shadow/internal/policy"
	"shadow/internal/store"
)

// fixtureDispatcher is an internal, read-only bridge between trusted action
// rules and the fixture fetcher. A test-only agent path may use its recorded
// read method; auth and test-write rules cannot execute through this bridge.
type fixtureDispatcher struct {
	actions  *policy.ActionPolicy
	fetcher  *fetcher
	store    *store.Store
	runID    string
	snapshot store.RunSnapshot
	reads    map[string]string
}

// ReadActionID identifies one trusted GET/read rule without passing a URL
// through a model tool call. It is an identifier, not an authorization grant.
func ReadActionID(rule policy.ActionRule) string {
	digest := sha256.Sum256([]byte("shadow-read-v1\x00" + rule.Method + "\x00" + string(rule.Effect) + "\x00" + rule.URL))
	return hex.EncodeToString(digest[:])
}

func newFixtureDispatcher(ctx context.Context, st *store.Store, runID string, rules []policy.ActionRule, opts Options) (*fixtureDispatcher, error) {
	if st == nil || runID == "" {
		return nil, errors.New("fixture dispatcher requires a run store and id")
	}
	if !opts.AllowLoopback {
		return nil, errors.New("fixture dispatcher requires an explicit loopback fixture")
	}
	snapshot, err := st.RunSnapshot(ctx, runID)
	if err != nil {
		return nil, errors.New("fixture dispatcher requires an immutable run snapshot")
	}
	scope, err := policy.FromTarget(snapshot.Origin)
	if err != nil || scope.Origin != snapshot.Origin || snapshot.RunID != runID {
		return nil, errors.New("invalid fixture run scope")
	}
	actions, err := policy.NewActionPolicy(scope, rules)
	if err != nil {
		return nil, err
	}
	allowed := make([]string, 0, len(rules))
	reads := make(map[string]string)
	for _, rule := range rules {
		if !snapshot.AllowsAction(rule) {
			return nil, errors.New("fixture action is not in the run snapshot")
		}
		if rule.Effect == policy.EffectRead && rule.Method == http.MethodGet {
			allowed = append(allowed, rule.URL)
			reads[ReadActionID(rule)] = rule.URL
		}
	}
	// Caller-supplied URL lists cannot add routes to the dispatcher.
	opts.allowedURLs = allowed
	fetcher, err := newFetcher(ctx, scope, opts)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(fetcher.ipString()); ip == nil || !ip.IsLoopback() {
		return nil, errors.New("fixture dispatcher requires a loopback destination")
	}
	d := &fixtureDispatcher{actions: actions, fetcher: fetcher, store: st, runID: runID, snapshot: snapshot, reads: reads}
	fetcher.guard = func(ctx context.Context, raw string) error { return d.authorize(ctx, http.MethodGet, raw) }
	fetcher.deny = d.recordDenied
	bindFixtureBudget(fetcher, st, runID, false)
	return d, nil
}

func (d *fixtureDispatcher) recordDenied(ctx context.Context, raw string) error {
	if d == nil || d.store == nil {
		return errors.New("fixture dispatcher unavailable")
	}
	current, err := d.store.RunSnapshot(ctx, d.runID)
	if err != nil || !reflect.DeepEqual(current, d.snapshot) {
		return errors.New("fixture run snapshot is unavailable or changed")
	}
	return d.store.RecordFixtureNetworkDecision(ctx, current, http.MethodGet, raw, false)
}

func (d *fixtureDispatcher) authorize(ctx context.Context, method, raw string) error {
	if d == nil || d.actions == nil || d.fetcher == nil || d.store == nil {
		return errors.New("fixture dispatcher unavailable")
	}
	current, err := d.store.RunSnapshot(ctx, d.runID)
	if err != nil || !reflect.DeepEqual(current, d.snapshot) {
		return errors.New("fixture run snapshot is unavailable or changed")
	}
	decision := d.actions.Classify(method, raw)
	allowed := decision.Allowed && decision.Rule.Effect == policy.EffectRead && method == http.MethodGet && current.AllowsAction(decision.Rule)
	if err := d.store.RecordFixtureNetworkDecision(ctx, current, method, raw, allowed); err != nil {
		return err
	}
	if !allowed {
		return errors.New("fixture request denied by action policy")
	}
	return nil
}

// ReadActionIDs returns only route identifiers for the model-facing fixture
// tool. The URL mapping stays in this run-bound dispatcher.
func (d *fixtureDispatcher) ReadActionIDs() []string {
	if d == nil {
		return nil
	}
	ids := make([]string, 0, len(d.reads))
	for id := range d.reads {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (d *fixtureDispatcher) ReadRecorded(ctx context.Context, actionID string) (Observation, int64, error) {
	if d == nil {
		return Observation{}, 0, errors.New("fixture read unavailable")
	}
	raw, ok := d.reads[actionID]
	if !ok {
		return Observation{}, 0, errors.New("fixture read action is not granted")
	}
	return d.getRecorded(ctx, http.MethodGet, raw)
}

func (d *fixtureDispatcher) getUnrecorded(ctx context.Context, method, raw string) (Observation, error) {
	if d == nil || method != http.MethodGet {
		return Observation{}, errors.New("fixture read method denied")
	}
	return d.fetcher.getObservation(ctx, raw)
}

func (d *fixtureDispatcher) getRecorded(ctx context.Context, method, raw string) (Observation, int64, error) {
	if d == nil || method != http.MethodGet {
		return Observation{}, 0, errors.New("fixture read method denied")
	}
	if !d.store.EvidenceKeyReady() {
		return Observation{}, 0, errors.New("fixture evidence key is unavailable")
	}
	observation, evidence, err := d.fetcher.get(ctx, raw)
	if err != nil {
		return Observation{}, 0, err
	}
	id, err := d.store.RecordObservationForSnapshot(ctx, d.snapshot, store.EvidenceSummary(observation), evidence)
	if err != nil {
		return Observation{}, 0, err
	}
	return observation, id, nil
}

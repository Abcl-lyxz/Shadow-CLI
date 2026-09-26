package broker

import (
	"context"
	"errors"
	"net"
	"net/http"
	"reflect"

	"shadow/internal/policy"
	"shadow/internal/store"
)

// FixtureDispatcher is an internal, read-only bridge between trusted action
// rules and the fixture fetcher. It is never exposed to agent tools. Auth and
// test-write rules can be classified, but cannot execute through this bridge.
type FixtureDispatcher struct {
	actions  *policy.ActionPolicy
	fetcher  *Fetcher
	store    *store.Store
	runID    string
	snapshot store.RunSnapshot
}

func NewFixtureDispatcher(ctx context.Context, st *store.Store, runID string, rules []policy.ActionRule, opts Options) (*FixtureDispatcher, error) {
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
	for _, rule := range rules {
		if !snapshot.AllowsAction(rule) {
			return nil, errors.New("fixture action is not in the run snapshot")
		}
		if rule.Effect == policy.EffectRead && rule.Method == http.MethodGet {
			allowed = append(allowed, rule.URL)
		}
	}
	// Caller-supplied URL lists cannot add routes to the dispatcher.
	opts.AllowedURLs = allowed
	fetcher, err := New(ctx, scope, opts)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(fetcher.IP()); ip == nil || !ip.IsLoopback() {
		return nil, errors.New("fixture dispatcher requires a loopback destination")
	}
	d := &FixtureDispatcher{actions: actions, fetcher: fetcher, store: st, runID: runID, snapshot: snapshot}
	fetcher.guard = func(ctx context.Context, raw string) error { return d.authorize(ctx, http.MethodGet, raw) }
	return d, nil
}

func (d *FixtureDispatcher) authorize(ctx context.Context, method, raw string) error {
	if d == nil || d.actions == nil || d.fetcher == nil || d.store == nil {
		return errors.New("fixture dispatcher unavailable")
	}
	current, err := d.store.RunSnapshot(ctx, d.runID)
	if err != nil || !reflect.DeepEqual(current, d.snapshot) {
		return errors.New("fixture run snapshot is unavailable or changed")
	}
	decision := d.actions.Classify(method, raw)
	if !decision.Allowed || decision.Rule.Effect != policy.EffectRead || method != http.MethodGet || !current.AllowsAction(decision.Rule) {
		return errors.New("fixture request denied by action policy")
	}
	return nil
}

func (d *FixtureDispatcher) Get(ctx context.Context, method, raw string) (Observation, error) {
	if err := d.authorize(ctx, method, raw); err != nil {
		return Observation{}, err
	}
	return d.fetcher.Get(ctx, raw)
}

func (d *FixtureDispatcher) GetRecorded(ctx context.Context, method, raw string) (Observation, int64, error) {
	if err := d.authorize(ctx, method, raw); err != nil {
		return Observation{}, 0, err
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

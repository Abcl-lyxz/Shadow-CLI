package broker

import (
	"context"
	"errors"
	"net"
	"net/http"

	"shadow/internal/policy"
	"shadow/internal/store"
)

// FixtureDispatcher is an internal, read-only bridge between trusted action
// rules and the fixture fetcher. It is never exposed to agent tools. Auth and
// test-write rules can be classified, but cannot execute through this bridge.
type FixtureDispatcher struct {
	actions *policy.ActionPolicy
	fetcher *Fetcher
}

func NewFixtureDispatcher(ctx context.Context, scope policy.Scope, rules []policy.ActionRule, opts Options) (*FixtureDispatcher, error) {
	if !opts.AllowLoopback {
		return nil, errors.New("fixture dispatcher requires an explicit loopback fixture")
	}
	actions, err := policy.NewActionPolicy(scope, rules)
	if err != nil {
		return nil, err
	}
	allowed := make([]string, 0, len(rules))
	for _, rule := range rules {
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
	return &FixtureDispatcher{actions: actions, fetcher: fetcher}, nil
}

func (d *FixtureDispatcher) authorize(method, raw string) error {
	if d == nil || d.actions == nil || d.fetcher == nil {
		return errors.New("fixture dispatcher unavailable")
	}
	decision := d.actions.Classify(method, raw)
	if !decision.Allowed || decision.Rule.Effect != policy.EffectRead || method != http.MethodGet {
		return errors.New("fixture request denied by action policy")
	}
	return nil
}

func (d *FixtureDispatcher) Get(ctx context.Context, method, raw string) (Observation, error) {
	if err := d.authorize(method, raw); err != nil {
		return Observation{}, err
	}
	return d.fetcher.Get(ctx, raw)
}

func (d *FixtureDispatcher) GetRecorded(ctx context.Context, method, runID, raw string, st *store.Store) (Observation, int64, error) {
	if err := d.authorize(method, raw); err != nil {
		return Observation{}, 0, err
	}
	return d.fetcher.GetRecorded(ctx, runID, raw, st)
}

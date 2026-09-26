package broker

import (
	"context"
	"errors"
	"net"
	"net/http"
	"reflect"
	"sort"
	"time"

	"shadow/internal/policy"
	"shadow/internal/store"
)

// ApprovedReadNetwork is the typed, read-only gateway for locally approved
// rules. It is not exposed to the shipped agent or UI. Authentication and
// mutations require separate host-owned contracts and remain unavailable.
type ApprovedReadNetwork struct {
	store    *store.Store
	snapshot store.RunSnapshot
	verified policy.VerifiedRules
	actions  *policy.ActionPolicy
	fetcher  *fetcher
	reads    map[string]string
}

// NewApprovedReadNetwork rejects loopback, private, and otherwise blocked DNS
// destinations. A local approval does not establish target-owner permission.
func NewApprovedReadNetwork(ctx context.Context, st *store.Store, runID string, verified policy.VerifiedRules) (*ApprovedReadNetwork, error) {
	return newApprovedReadNetwork(ctx, st, runID, verified, Options{}, false)
}

func newApprovedReadNetwork(ctx context.Context, st *store.Store, runID string, verified policy.VerifiedRules, opts Options, controlledLoopback bool) (*ApprovedReadNetwork, error) {
	if st == nil || runID == "" || verified.ApprovalID() == "" || !time.Now().Before(verified.ExpiresAt()) || !st.EvidenceKeyReady() {
		return nil, errors.New("approved read requires an active run, approval, and evidence key")
	}
	snapshot, err := st.RunSnapshot(ctx, runID)
	if err != nil || snapshot.RunID != runID || snapshot.Origin != verified.Origin() {
		return nil, errors.New("approved read run snapshot is unavailable or changed")
	}
	if err := sameRunApproval(ctx, st, runID, verified); err != nil {
		return nil, err
	}
	rules := verified.Actions()
	if len(rules) == 0 || len(rules) != len(snapshot.Actions) {
		return nil, errors.New("approved read requires the exact run action set")
	}
	scope, err := policy.FromTarget(snapshot.Origin)
	if err != nil || scope.Origin != snapshot.Origin {
		return nil, errors.New("invalid approved read origin")
	}
	actions, err := policy.NewActionPolicy(scope, rules)
	if err != nil {
		return nil, err
	}
	allowed := make([]string, 0, len(rules))
	reads := make(map[string]string, len(rules))
	for _, rule := range rules {
		if rule.Effect != policy.EffectRead || rule.Method != http.MethodGet || !snapshot.AllowsAction(rule) {
			return nil, errors.New("approved read accepts only exact GET/read grants")
		}
		allowed = append(allowed, rule.URL)
		reads[ReadActionID(rule)] = rule.URL
	}
	opts.allowedURLs = allowed
	opts.AllowLoopback = controlledLoopback
	fetch, err := newFetcher(ctx, scope, opts)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(fetch.ipString()); ip == nil || ip.IsLoopback() != controlledLoopback {
		return nil, errors.New("approved read destination class is not allowed")
	}
	n := &ApprovedReadNetwork{store: st, snapshot: snapshot, verified: verified, actions: actions, fetcher: fetch, reads: reads}
	fetch.guard = n.authorize
	fetch.deny = n.recordDenied
	bindFixtureBudget(fetch, st, runID, false)
	return n, nil
}

func sameRunApproval(ctx context.Context, st *store.Store, runID string, verified policy.VerifiedRules) error {
	id, digest, expires, err := st.RunRuleApproval(ctx, runID)
	if err != nil || id != verified.ApprovalID() || digest != verified.RulesSHA256() || !expires.Equal(verified.ExpiresAt()) || !time.Now().Before(expires) {
		return errors.New("approved read has no matching unexpired run approval")
	}
	return nil
}

func (n *ApprovedReadNetwork) current(ctx context.Context) (store.RunSnapshot, error) {
	if n == nil || n.store == nil {
		return store.RunSnapshot{}, errors.New("approved read unavailable")
	}
	current, err := n.store.RunSnapshot(ctx, n.snapshot.RunID)
	if err != nil || !reflect.DeepEqual(current, n.snapshot) {
		return store.RunSnapshot{}, errors.New("approved read run snapshot is unavailable or changed")
	}
	if err := sameRunApproval(ctx, n.store, n.snapshot.RunID, n.verified); err != nil {
		return store.RunSnapshot{}, err
	}
	return current, nil
}

func (n *ApprovedReadNetwork) recordDenied(ctx context.Context, raw string) error {
	current, err := n.current(ctx)
	if err != nil {
		return err
	}
	return n.store.RecordApprovedReadDecision(ctx, current, raw, false, n.verified.ApprovalID(), n.verified.RulesSHA256())
}

func (n *ApprovedReadNetwork) authorize(ctx context.Context, raw string) error {
	current, err := n.current(ctx)
	if err != nil {
		return err
	}
	decision := n.actions.Classify(http.MethodGet, raw)
	allowed := decision.Allowed && decision.Rule.Effect == policy.EffectRead && current.AllowsAction(decision.Rule)
	if err := n.store.RecordApprovedReadDecision(ctx, current, raw, allowed, n.verified.ApprovalID(), n.verified.RulesSHA256()); err != nil {
		return err
	}
	if !allowed {
		return errors.New("approved read route denied")
	}
	return nil
}

func (n *ApprovedReadNetwork) ReadActionIDs() []string {
	if n == nil {
		return nil
	}
	ids := make([]string, 0, len(n.reads))
	for id := range n.reads {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (n *ApprovedReadNetwork) ReadRecorded(ctx context.Context, actionID string) (Observation, int64, error) {
	if n == nil {
		return Observation{}, 0, errors.New("approved read unavailable")
	}
	raw, ok := n.reads[actionID]
	if !ok {
		return Observation{}, 0, errors.New("approved read action is not granted")
	}
	if _, err := n.current(ctx); err != nil {
		return Observation{}, 0, err
	}
	if !n.store.EvidenceKeyReady() {
		return Observation{}, 0, errors.New("approved read evidence key is unavailable")
	}
	observation, evidence, err := n.fetcher.get(ctx, raw)
	if err != nil {
		return Observation{}, 0, err
	}
	id, err := n.store.RecordObservationForSnapshot(ctx, n.snapshot, store.EvidenceSummary(observation), evidence)
	if err != nil {
		return Observation{}, 0, err
	}
	return observation, id, nil
}

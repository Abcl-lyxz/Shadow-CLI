package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"sort"

	"shadow/internal/policy"
	"shadow/internal/store"
)

// FixtureRunNetwork is the typed, run-bound entry point for local fixture
// actions. It never grants public-target access or arbitrary request bodies.
type FixtureRunNetwork struct {
	store    *store.Store
	snapshot store.RunSnapshot
	reads    *fixtureDispatcher
	writes   map[string]*fixtureWriteDispatcher
	cleanups map[string]*fixtureCleanupExecutor
	auth     map[string]*fixtureAuthenticator
}

func fixtureActionID(kind string, rule policy.ActionRule) string {
	digest := sha256.Sum256([]byte("shadow-fixture-" + kind + "-v1\x00" + rule.Method + "\x00" + string(rule.Effect) + "\x00" + rule.URL + "\x00" + rule.Resource + "\x00" + rule.CleanupMethod + "\x00" + rule.CleanupURL))
	return hex.EncodeToString(digest[:])
}

func FixtureWriteActionID(rule policy.ActionRule) string { return fixtureActionID("write", rule) }
func FixtureAuthActionID(rule policy.ActionRule) string  { return fixtureActionID("auth", rule) }

// NewFixtureRunNetwork accepts only trusted rules already stored in the run
// snapshot. Extra caller-supplied URLs and unimplemented mutation contracts
// cannot expand its network access.
func NewFixtureRunNetwork(ctx context.Context, st *store.Store, runID string, rules []policy.ActionRule, opts Options) (*FixtureRunNetwork, error) {
	if st == nil || runID == "" || !opts.AllowLoopback {
		return nil, errors.New("fixture network requires a run store and explicit loopback destination")
	}
	snapshot, err := st.RunSnapshot(ctx, runID)
	if err != nil || snapshot.RunID != runID {
		return nil, errors.New("fixture network requires an immutable run snapshot")
	}
	scope, err := policy.FromTarget(snapshot.Origin)
	if err != nil || scope.Origin != snapshot.Origin {
		return nil, errors.New("invalid fixture network scope")
	}
	if _, err := policy.NewActionPolicy(scope, rules); err != nil {
		return nil, err
	}
	reads := make([]policy.ActionRule, 0)
	writeRules := make([]policy.ActionRule, 0)
	network := &FixtureRunNetwork{store: st, snapshot: snapshot, writes: make(map[string]*fixtureWriteDispatcher), cleanups: make(map[string]*fixtureCleanupExecutor), auth: make(map[string]*fixtureAuthenticator)}
	authRules := make([]policy.ActionRule, 0)
	for _, rule := range rules {
		if !snapshot.AllowsAction(rule) {
			return nil, errors.New("fixture network rule is not in the run snapshot")
		}
		switch rule.Effect {
		case policy.EffectRead:
			if rule.Method == http.MethodGet {
				reads = append(reads, rule)
			}
		case policy.EffectAuth:
			authRules = append(authRules, rule)
		case policy.EffectTestWrite:
			if rule.Method != http.MethodPost {
				return nil, errors.New("fixture network supports only fixed marker POST writes")
			}
			writeRules = append(writeRules, rule)
		}
	}
	if len(reads) != 0 {
		network.reads, err = newFixtureDispatcher(ctx, st, runID, reads, opts)
		if err != nil {
			return nil, err
		}
	}
	for _, rule := range authRules {
		auth, err := newFixtureAuthenticator(ctx, st, snapshot, rule, network.reads, opts)
		if err != nil {
			return nil, err
		}
		network.auth[FixtureAuthActionID(rule)] = auth
	}
	for _, write := range writeRules {
		var matching *policy.ActionRule
		for i := range reads {
			if reads[i].URL == write.CleanupURL {
				matching = &reads[i]
				break
			}
		}
		if matching == nil {
			return nil, errors.New("fixture write lacks an exact cleanup read grant")
		}
		writer, err := newFixtureWriteDispatcher(ctx, st, runID, write, *matching, opts)
		if err != nil {
			return nil, err
		}
		cleanup, err := newFixtureCleanupExecutor(ctx, st, runID, write, *matching, opts)
		if err != nil {
			return nil, err
		}
		if network.reads == nil || writer.writer.ipString() != network.reads.fetcher.ipString() || cleanup.cleanup.ipString() != network.reads.fetcher.ipString() {
			return nil, errors.New("fixture action destinations do not share one pinned IP")
		}
		id := FixtureWriteActionID(write)
		network.writes[id], network.cleanups[id] = writer, cleanup
	}
	return network, nil
}

func sortedActionIDs[T any](actions map[string]T) []string {
	ids := make([]string, 0, len(actions))
	for id := range actions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (n *FixtureRunNetwork) ReadActionIDs() []string {
	if n == nil || n.reads == nil {
		return nil
	}
	return n.reads.ReadActionIDs()
}

func (n *FixtureRunNetwork) WriteActionIDs() []string {
	if n == nil {
		return nil
	}
	return sortedActionIDs(n.writes)
}

func (n *FixtureRunNetwork) AuthActionIDs() []string {
	if n == nil {
		return nil
	}
	return sortedActionIDs(n.auth)
}

func (n *FixtureRunNetwork) ReadRecorded(ctx context.Context, actionID string) (Observation, int64, error) {
	if n == nil || n.reads == nil {
		return Observation{}, 0, errors.New("fixture read unavailable")
	}
	return n.reads.ReadRecorded(ctx, actionID)
}

// Authenticate resolves a run-bound credential at dispatch and keeps the
// resulting cookie only in this adapter's memory.
func (n *FixtureRunNetwork) Authenticate(ctx context.Context, actionID string) error {
	if n == nil {
		return errors.New("fixture authentication unavailable")
	}
	auth, ok := n.auth[actionID]
	if !ok {
		return errors.New("fixture authentication action is not granted")
	}
	return auth.authenticate(ctx, actionID)
}

// ReadAuthenticated attaches the session only to a snapshotted read action at
// the same origin. A new network instance has no session until login succeeds.
func (n *FixtureRunNetwork) ReadAuthenticated(ctx context.Context, authActionID, readActionID string) (Observation, int64, error) {
	if n == nil {
		return Observation{}, 0, errors.New("fixture session unavailable")
	}
	auth, ok := n.auth[authActionID]
	if !ok {
		return Observation{}, 0, errors.New("fixture authentication action is not granted")
	}
	return auth.read(ctx, readActionID)
}

func (n *FixtureRunNetwork) WriteMarker(ctx context.Context, actionID string) (int64, int64, error) {
	return n.writeResource(ctx, actionID, store.FixtureMarkerProtocolV1)
}

func (n *FixtureRunNetwork) WriteRecord(ctx context.Context, actionID string) (int64, int64, error) {
	return n.writeResource(ctx, actionID, store.FixtureRecordProtocolV1)
}

func (n *FixtureRunNetwork) writeResource(ctx context.Context, actionID, protocol string) (int64, int64, error) {
	if n == nil {
		return 0, 0, errors.New("fixture write unavailable")
	}
	write, ok := n.writes[actionID]
	if !ok || write.protocol.id() != protocol {
		return 0, 0, errors.New("fixture write action is not granted")
	}
	return write.Dispatch(ctx)
}

func (n *FixtureRunNetwork) CleanupMarker(ctx context.Context, actionID string, testActionID, presenceEventID int64) (int64, error) {
	return n.cleanupResource(ctx, actionID, testActionID, presenceEventID, store.FixtureMarkerProtocolV1)
}

func (n *FixtureRunNetwork) CleanupRecord(ctx context.Context, actionID string, testActionID, presenceEventID int64) (int64, error) {
	return n.cleanupResource(ctx, actionID, testActionID, presenceEventID, store.FixtureRecordProtocolV1)
}

func (n *FixtureRunNetwork) cleanupResource(ctx context.Context, actionID string, testActionID, presenceEventID int64, protocol string) (int64, error) {
	if n == nil {
		return 0, errors.New("fixture cleanup unavailable")
	}
	cleanup, ok := n.cleanups[actionID]
	if !ok || cleanup.protocol.id() != protocol {
		return 0, errors.New("fixture cleanup action is not granted")
	}
	return cleanup.Cleanup(ctx, testActionID, presenceEventID)
}

func (n *FixtureRunNetwork) InspectWrite(ctx context.Context, actionID string, testActionID int64) (int64, error) {
	if n == nil {
		return 0, errors.New("fixture write inspection unavailable")
	}
	cleanup, ok := n.cleanups[actionID]
	if !ok {
		return 0, errors.New("fixture write action is not granted")
	}
	return cleanup.InspectWrite(ctx, testActionID)
}

func (n *FixtureRunNetwork) InspectCleanup(ctx context.Context, actionID string, testActionID, presenceEventID int64) (int64, error) {
	if n == nil {
		return 0, errors.New("fixture cleanup inspection unavailable")
	}
	cleanup, ok := n.cleanups[actionID]
	if !ok {
		return 0, errors.New("fixture cleanup action is not granted")
	}
	return cleanup.InspectCleanup(ctx, testActionID, presenceEventID)
}

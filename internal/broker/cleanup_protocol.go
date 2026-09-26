package broker

import (
	"context"
	"errors"
	"net/http"

	"shadow/internal/policy"
	"shadow/internal/store"
)

// cleanupState describes the observed resource state. An HTTP success code or
// an unrecognized response is never enough to establish cleanup.
type cleanupState uint8

const (
	cleanupUnknown cleanupState = iota
	cleanupPresent
	cleanupAbsent
)

// cleanupProtocol is selected by trusted runtime code, never by a model or
// target response. Future target protocols must provide their own semantic
// evidence checks before a journal obligation can be resolved.
type cleanupProtocol interface {
	id() string
	inspect(store.EvidenceSummary, store.RawHTTP) cleanupState
	verify(context.Context, *store.Store, string, int64, int64) error
}

func newFixtureProtocol(write, read policy.ActionRule) (cleanupProtocol, error) {
	id, err := store.FixtureProtocolForRule(write)
	if err != nil {
		return nil, err
	}
	if id == store.FixtureRecordProtocolV1 {
		marker, err := newFixtureMarkerProtocol(write, read)
		if err != nil {
			return nil, err
		}
		p := marker.(fixtureMarkerProtocol)
		return fixtureRecordProtocol(p), nil
	}
	return newFixtureMarkerProtocol(write, read)
}

type fixtureMarkerProtocol struct {
	readURL  string
	resource string
}

func newFixtureMarkerProtocol(write, read policy.ActionRule) (cleanupProtocol, error) {
	if write.Effect != policy.EffectTestWrite || write.Method != http.MethodPost ||
		write.CleanupMethod != http.MethodDelete || read.Effect != policy.EffectRead ||
		read.Method != http.MethodGet || read.URL != write.CleanupURL {
		return nil, errors.New("fixture marker cleanup requires an exact write, delete, and read contract")
	}
	scope, err := policy.FromTarget(write.URL)
	if err != nil {
		return nil, err
	}
	if _, err := policy.NewActionPolicy(scope, []policy.ActionRule{write, read}); err != nil {
		return nil, err
	}
	return fixtureMarkerProtocol{readURL: read.URL, resource: write.Resource}, nil
}

func (p fixtureMarkerProtocol) inspect(summary store.EvidenceSummary, raw store.RawHTTP) cleanupState {
	if store.FixtureMarkerState(summary, raw, p.readURL, p.resource, true) {
		return cleanupPresent
	}
	if store.FixtureMarkerState(summary, raw, p.readURL, p.resource, false) {
		return cleanupAbsent
	}
	return cleanupUnknown
}

func (p fixtureMarkerProtocol) id() string { return store.FixtureMarkerProtocolV1 }

func (p fixtureMarkerProtocol) verify(ctx context.Context, st *store.Store, runID string, actionID, presenceEventID int64) error {
	return st.VerifyFixtureCleanup(ctx, runID, actionID, presenceEventID, p.readURL, p.id())
}

type fixtureRecordProtocol fixtureMarkerProtocol

func (p fixtureRecordProtocol) id() string { return store.FixtureRecordProtocolV1 }
func (p fixtureRecordProtocol) inspect(summary store.EvidenceSummary, raw store.RawHTTP) cleanupState {
	if store.FixtureRecordState(summary, raw, p.readURL, p.resource, true) {
		return cleanupPresent
	}
	if store.FixtureRecordState(summary, raw, p.readURL, p.resource, false) {
		return cleanupAbsent
	}
	return cleanupUnknown
}
func (p fixtureRecordProtocol) verify(ctx context.Context, st *store.Store, runID string, actionID, presenceEventID int64) error {
	return st.VerifyFixtureCleanup(ctx, runID, actionID, presenceEventID, p.readURL, p.id())
}

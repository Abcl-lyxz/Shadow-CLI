package broker

import (
	"net/http"
	"testing"

	"shadow/internal/policy"
	"shadow/internal/store"
)

func TestFixtureCleanupProtocolRequiresSemanticEvidence(t *testing.T) {
	write := policy.ActionRule{
		URL: "http://127.0.0.1:8080/markers", Method: http.MethodPost,
		Effect: policy.EffectTestWrite, Resource: "shadow_marker_1",
		CleanupURL: "http://127.0.0.1:8080/markers/shadow_marker_1", CleanupMethod: http.MethodDelete,
	}
	read := policy.ActionRule{URL: write.CleanupURL, Method: http.MethodGet, Effect: policy.EffectRead}
	protocol, err := newFixtureMarkerProtocol(write, read)
	if err != nil {
		t.Fatal(err)
	}
	raw := store.RawHTTP{RequestURL: read.URL, Method: http.MethodGet, Body: []byte(`{"resource":"shadow_marker_1","present":true}`)}
	summary := store.EvidenceSummary{Status: http.StatusOK, ContentType: "application/json"}
	if got := protocol.inspect(summary, raw); got != cleanupPresent {
		t.Fatalf("present marker classified as %v", got)
	}
	raw.Body = []byte(`{"resource":"shadow_marker_1","present":false}`)
	summary.Status = http.StatusNotFound
	if got := protocol.inspect(summary, raw); got != cleanupAbsent {
		t.Fatalf("absent marker classified as %v", got)
	}
	summary.Status = http.StatusNoContent
	if got := protocol.inspect(summary, raw); got != cleanupUnknown {
		t.Fatalf("status alone established cleanup: %v", got)
	}
	summary.Status = http.StatusNotFound
	raw.RequestURL += "?different=1"
	if got := protocol.inspect(summary, raw); got != cleanupUnknown {
		t.Fatalf("different route established cleanup: %v", got)
	}
	write.Resource = "production_record"
	if _, err := newFixtureMarkerProtocol(write, read); err == nil {
		t.Fatal("unbounded resource accepted as a cleanup contract")
	}
}

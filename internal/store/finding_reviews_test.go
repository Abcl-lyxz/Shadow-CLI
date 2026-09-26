package store

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

func TestFindingReviewEventBindingAndPurge(t *testing.T) {
	ctx := context.Background()
	st, err := OpenWithEvidenceKey(filepath.Join(t.TempDir(), "shadow.db"), bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	summary, raw := responseFixture(t, "review")
	source, err := st.RecordObservation(ctx, "run-1", summary, raw)
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.CreateFinding(ctx, "run-1", "review", "http://fixture.test", ClaimSecurityHypothesis, source)
	if err != nil {
		t.Fatal(err)
	}
	r, err := st.ReviewFinding(ctx, "run-1", id, "blocked", "low", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := st.FindingReviews(ctx, "run-1"); err != nil || got[id].ReviewEventID != r.ReviewEventID {
		t.Fatalf("review lookup: %v %#v", err, got)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE finding_reviews SET confidence='high' WHERE finding_id=?", id); err != nil {
		t.Fatal(err)
	}
	if _, err := st.FindingReviews(ctx, "run-1"); err == nil {
		t.Fatal("edited review escaped event binding")
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE finding_reviews SET confidence='low' WHERE finding_id=?", id); err != nil {
		t.Fatal(err)
	}
	if err := st.PurgeRun(ctx, "run-1"); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := st.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM finding_reviews").Scan(&count); err != nil || count != 0 {
		t.Fatalf("review retained after purge: %d %v", count, err)
	}
}

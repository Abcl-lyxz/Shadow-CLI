package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestInMemorySnapshotEnforcesLimitAndOpensWithoutWAL(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Append(ctx, "run-1", "note", map[string]string{"text": "checkpoint"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SnapshotBytes(ctx, 1); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized in-memory backup accepted: %v", err)
	}
	image, err := st.SnapshotBytes(ctx, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySnapshotBytes(ctx, image, nil); err != nil {
		t.Fatalf("standalone image rejected: %v", err)
	}
}

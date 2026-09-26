package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestEventHeadsExposeOnlyBoundedDecisionMetadata(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.Append(ctx, "run", "network_decision", map[string]any{"method": "GET", "allowed": false, "url_sha256": "sensitive-hash"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Append(ctx, "run", "tool", map[string]any{"secret": "private-payload"}); err != nil {
		t.Fatal(err)
	}
	heads, err := st.EventHeads(ctx, "run", 2)
	if err != nil || len(heads) != 2 {
		t.Fatalf("heads %v %v", heads, err)
	}
	if heads[0].Method != "GET" || heads[0].Allowed == nil || *heads[0].Allowed || heads[0].Payload != nil || heads[1].Payload != nil {
		t.Fatalf("unsafe heads %+v", heads)
	}
	last, err := st.EventHeads(ctx, "run", 1)
	if err != nil || len(last) != 1 || last[0].Kind != "tool" {
		t.Fatalf("limit %v %v", last, err)
	}
}

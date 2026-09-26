package store

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"shadow/internal/policy"
)

func TestAgentPlanSealDetectsChangedBudget(t *testing.T) {
	ctx := context.Background()
	st, err := Open(filepath.Join(t.TempDir(), "shadow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	scope, _ := policy.FromTarget("https://example.com")
	if err := st.StartRun(ctx, "plan", scope, nil); err != nil {
		t.Fatal(err)
	}
	budget, _ := json.Marshal(map[string]int{"max_steps": 4})
	if err := st.CreateAgentPlan(ctx, "plan", PromptDigest("task"), []byte(`{"model":"one"}`), budget, []string{"source"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE agent_plans SET budget=? WHERE run_id='plan'", []byte(`{"max_steps":8}`)); err == nil {
		t.Fatal("immutable plan changed")
	}
	if _, err := st.db.ExecContext(ctx, "DROP TRIGGER immutable_agent_plan"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, "UPDATE agent_plans SET budget=? WHERE run_id='plan'", []byte(`{"max_steps":8}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.AgentPlan(ctx, "plan"); err == nil {
		t.Fatal("changed budget passed durable event seal")
	}
}

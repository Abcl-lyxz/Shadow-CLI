package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"shadow/internal/policy"
)

// AgentJob contains only operational metadata. Instructions, provider replies,
// and tool arguments never enter the checkpoint table or its events.
type AgentJob struct {
	Role         string
	Status       string
	Phase        string
	Step         int
	InputTokens  int64
	OutputTokens int64
	CostMicroUSD int64
	ToolCalls    int
}

type AgentPlan struct {
	RunID        string
	PromptSHA256 string
	Route        []byte
	Budget       []byte
	Jobs         []AgentJob
}

func (s *Store) AgentPlanIDs(ctx context.Context, limit int) ([]string, error) {
	if limit < 1 || limit > 50 {
		limit = 10
	}
	rows, err := s.db.QueryContext(ctx, "SELECT run_id FROM agent_plans ORDER BY created_at DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func PromptDigest(prompt string) string {
	sum := sha256.Sum256([]byte(prompt))
	return hex.EncodeToString(sum[:])
}

func bytesDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func (s *Store) CreateAgentPlan(ctx context.Context, runID, promptSHA256 string, route, budget []byte, roles []string) error {
	if runID == "" || len(promptSHA256) != 64 || len(route) == 0 || len(route) > 4096 || len(budget) == 0 || len(budget) > 4096 || len(roles) == 0 || len(roles) > 8 {
		return errors.New("invalid agent plan")
	}
	if _, err := hex.DecodeString(promptSHA256); err != nil {
		return errors.New("invalid prompt digest")
	}
	seen := map[string]bool{}
	for _, role := range roles {
		if role == "" || len(role) > 32 || seen[role] {
			return errors.New("invalid or duplicate agent role")
		}
		seen[role] = true
	}
	unlock, err := s.beginProvenanceMutation(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var actions []byte
	if err := tx.QueryRowContext(ctx, "SELECT actions FROM run_snapshots WHERE run_id=?", runID).Scan(&actions); err != nil {
		return err
	}
	if string(actions) != "[]" {
		var grants []ActionGrant
		if err := json.Unmarshal(actions, &grants); err != nil || len(grants) == 0 || len(grants) > 20 || !seen["surface"] {
			return errors.New("approved agent plan requires bounded read grants and a surface role")
		}
		for _, grant := range grants {
			if grant.Method != "GET" || grant.Effect != policy.EffectRead || grant.Resource != "" || grant.CleanupMethod != "" || grant.CleanupURLSHA256 != "" {
				return errors.New("agent plan cannot contain target mutations")
			}
		}
		var approvalID, digest, expiry string
		if err := tx.QueryRowContext(ctx, "SELECT approval_id,rules_sha256,expires_at FROM run_rule_approvals WHERE run_id=?", runID).Scan(&approvalID, &digest, &expiry); err != nil || approvalID == "" || digest == "" {
			return errors.New("approved agent plan requires an immutable run approval")
		}
		expiresAt, err := time.Parse(time.RFC3339, expiry)
		if err != nil || !time.Now().Before(expiresAt) {
			return errors.New("approved agent plan requires an unexpired approval")
		}
		var start []byte
		if err := tx.QueryRowContext(ctx, "SELECT payload FROM events WHERE run_id=? AND kind='started' ORDER BY id LIMIT 1", runID).Scan(&start); err != nil {
			return err
		}
		var recorded struct {
			ApprovalID string `json:"rule_approval_id"`
			Digest     string `json:"rules_sha256"`
			Expiry     string `json:"rule_approval_expires_at"`
		}
		if err := json.Unmarshal(start, &recorded); err != nil || recorded.ApprovalID != approvalID || recorded.Digest != digest || recorded.Expiry != expiry {
			return errors.New("approved agent plan differs from its run start")
		}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, "INSERT INTO agent_plans(run_id,prompt_sha256,route,budget,created_at) VALUES(?,?,?,?,?)", runID, promptSHA256, route, budget, now); err != nil {
		return err
	}
	for _, role := range roles {
		if _, err := tx.ExecContext(ctx, "INSERT INTO agent_jobs(run_id,role,status,updated_at) VALUES(?,?,'pending',?)", runID, role, now); err != nil {
			return err
		}
	}
	if _, err := actionEvent(ctx, tx, runID, "agent_plan", map[string]any{"roles": roles, "prompt_sha256": promptSHA256, "route_sha256": bytesDigest(route), "budget_sha256": bytesDigest(budget)}); err != nil {
		return err
	}
	return s.commitWithProvenance(ctx, tx, "agent_plan")
}

func (s *Store) AgentPlan(ctx context.Context, runID string) (AgentPlan, error) {
	var plan AgentPlan
	plan.RunID = runID
	if err := s.db.QueryRowContext(ctx, "SELECT prompt_sha256,route,budget FROM agent_plans WHERE run_id=?", runID).Scan(&plan.PromptSHA256, &plan.Route, &plan.Budget); err != nil {
		return AgentPlan{}, err
	}
	var payload []byte
	if err := s.db.QueryRowContext(ctx, "SELECT payload FROM events WHERE run_id=? AND kind='agent_plan' ORDER BY id ASC LIMIT 1", runID).Scan(&payload); err != nil {
		return AgentPlan{}, err
	}
	var seal struct {
		PromptSHA256 string   `json:"prompt_sha256"`
		RouteSHA256  string   `json:"route_sha256"`
		BudgetSHA256 string   `json:"budget_sha256"`
		Roles        []string `json:"roles"`
	}
	if err := json.Unmarshal(payload, &seal); err != nil {
		return AgentPlan{}, err
	}
	if seal.PromptSHA256 != plan.PromptSHA256 || seal.RouteSHA256 != bytesDigest(plan.Route) || seal.BudgetSHA256 != bytesDigest(plan.Budget) {
		return AgentPlan{}, errors.New("agent plan differs from its durable event")
	}
	rows, err := s.db.QueryContext(ctx, "SELECT role,status,phase,step,input_tokens,output_tokens,cost_microusd,tool_calls FROM agent_jobs WHERE run_id=? ORDER BY role", runID)
	if err != nil {
		return AgentPlan{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var job AgentJob
		if err := rows.Scan(&job.Role, &job.Status, &job.Phase, &job.Step, &job.InputTokens, &job.OutputTokens, &job.CostMicroUSD, &job.ToolCalls); err != nil {
			return AgentPlan{}, err
		}
		plan.Jobs = append(plan.Jobs, job)
	}
	if err := rows.Err(); err != nil {
		return AgentPlan{}, err
	}
	if len(seal.Roles) != len(plan.Jobs) {
		return AgentPlan{}, errors.New("agent role set differs from durable plan")
	}
	seen := map[string]bool{}
	for _, role := range seal.Roles {
		seen[role] = true
	}
	for _, job := range plan.Jobs {
		if !seen[job.Role] {
			return AgentPlan{}, errors.New("agent role differs from durable plan")
		}
	}
	return plan, nil
}

// AgentJobTransition uses an exact expected state. A running job left by a
// dead process never becomes pending merely because a lease or timer expired.
func (s *Store) AgentJobTransition(ctx context.Context, runID, role, from, to, phase string, step int, input, output, cost int64, tools int) error {
	if runID == "" || role == "" || step < 0 || input < 0 || output < 0 || cost < 0 || tools < 0 {
		return errors.New("invalid agent checkpoint")
	}
	valid := from == "pending" && to == "running" || from == "running" && (to == "running" || to == "done" || to == "failed" || to == "interrupted") || from == "interrupted" && to == "pending"
	if !valid {
		return errors.New("invalid agent state transition")
	}
	unlock, err := s.beginProvenanceMutation(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE agent_jobs SET status=?,phase=?,step=?,input_tokens=?,output_tokens=?,cost_microusd=?,tool_calls=?,updated_at=?
		WHERE run_id=? AND role=? AND status=? AND step<=? AND input_tokens<=? AND output_tokens<=? AND cost_microusd<=? AND tool_calls<=?`,
		to, phase, step, input, output, cost, tools, time.Now().UTC().Format(time.RFC3339Nano), runID, role, from, step, input, output, cost, tools)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("agent state changed or checkpoint regressed")
	}
	if _, err := actionEvent(ctx, tx, runID, "agent_checkpoint", map[string]any{"role": role, "status": to, "phase": phase, "step": step, "input_tokens": input, "output_tokens": output, "cost_microusd": cost, "tool_calls": tools}); err != nil {
		return err
	}
	return s.commitWithProvenance(ctx, tx, "agent_checkpoint")
}

// RecoverAgentPlan is a local startup operation. It records uncertainty and
// never dispatches a provider or tool call. Explicit operator review is needed
// before RetryInterruptedAgentJob can move such a job back to pending.
func (s *Store) RecoverAgentPlan(ctx context.Context, runID string) (int, error) {
	plan, err := s.AgentPlan(ctx, runID)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, job := range plan.Jobs {
		if job.Status != "running" {
			continue
		}
		if err := s.AgentJobTransition(ctx, runID, job.Role, "running", "interrupted", "outcome_unknown", job.Step, job.InputTokens, job.OutputTokens, job.CostMicroUSD, job.ToolCalls); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func (s *Store) RetryInterruptedAgentJob(ctx context.Context, runID, role, reviewedOutcome string) error {
	if reviewedOutcome != "no_side_effect" && reviewedOutcome != "side_effect_resolved" {
		return errors.New("explicit outcome review required")
	}
	plan, err := s.AgentPlan(ctx, runID)
	if err != nil {
		return err
	}
	for _, job := range plan.Jobs {
		if job.Role == role {
			if job.Status != "interrupted" {
				return errors.New("job is not interrupted")
			}
			return s.AgentJobTransition(ctx, runID, role, "interrupted", "pending", "reviewed_"+reviewedOutcome, job.Step, job.InputTokens, job.OutputTokens, job.CostMicroUSD, job.ToolCalls)
		}
	}
	return sql.ErrNoRows
}

// VerifiedResponseMemory is a small, typed cross-agent reference. It cannot
// carry a vulnerability claim or free-form text into another agent's prompt.
type VerifiedResponseMemory struct {
	RunID         string
	SourceEventID int64
	RepeatEventID int64
	Status        int
	URLSHA256     string
	BodySHA256    string
	Confidence    string
	ExpiresAt     time.Time
}

func (s *Store) RecallVerifiedResponses(ctx context.Context, origin string, limit int) ([]VerifiedResponseMemory, error) {
	return s.recallVerifiedResponses(ctx, origin, limit, time.Now())
}

func (s *Store) recallVerifiedResponses(ctx context.Context, origin string, limit int, now time.Time) ([]VerifiedResponseMemory, error) {
	if origin == "" {
		return nil, errors.New("origin required")
	}
	if limit < 1 || limit > 20 {
		limit = 6
	}
	rows, err := s.db.QueryContext(ctx, `SELECT f.id,f.run_id,m.scope,m.source_event_id,m.repeat_event_id,m.confidence,m.expires_at,v.payload FROM verified_response_memory m JOIN findings f ON f.id=m.finding_id JOIN events v ON v.id=m.verification_event_id AND v.run_id=f.run_id AND v.kind='response_reproduced'
		WHERE m.scope=? AND f.asset=? AND f.claim_type=? AND f.status='verified' AND f.reproduction_event_id=m.repeat_event_id ORDER BY m.finding_id DESC LIMIT ?`, origin, origin, ClaimResponseObservation, limit)
	if err != nil {
		return nil, err
	}
	var refs []VerifiedResponseMemory
	for rows.Next() {
		var m VerifiedResponseMemory
		var expires, scope string
		var findingID int64
		var payload []byte
		if err := rows.Scan(&findingID, &m.RunID, &scope, &m.SourceEventID, &m.RepeatEventID, &m.Confidence, &expires, &payload); err != nil {
			rows.Close()
			return nil, err
		}
		var seal struct {
			FindingID           int64  `json:"finding_id"`
			SourceEventID       int64  `json:"source_event_id"`
			ReproductionEventID int64  `json:"reproduction_event_id"`
			Confidence          string `json:"confidence"`
			ExpiresAt           string `json:"expires_at"`
		}
		if err := json.Unmarshal(payload, &seal); err != nil {
			rows.Close()
			return nil, err
		}
		if scope != origin || seal.FindingID != findingID || seal.SourceEventID != m.SourceEventID || seal.ReproductionEventID != m.RepeatEventID || seal.Confidence != m.Confidence || seal.ExpiresAt != expires {
			rows.Close()
			return nil, errors.New("verified response memory differs from its event")
		}
		m.ExpiresAt, err = time.Parse(time.RFC3339Nano, expires)
		if err != nil {
			rows.Close()
			return nil, err
		}
		if m.Confidence != "reproduced_response" {
			rows.Close()
			return nil, errors.New("invalid verified response confidence")
		}
		if !m.ExpiresAt.After(now) {
			continue
		}
		refs = append(refs, m)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	var out []VerifiedResponseMemory
	for _, m := range refs {
		source, err := s.observationInRun(ctx, m.RunID, m.SourceEventID)
		if err != nil {
			return nil, fmt.Errorf("verified response source invalid: %w", err)
		}
		repeat, err := s.observationInRun(ctx, m.RunID, m.RepeatEventID)
		if err != nil {
			return nil, fmt.Errorf("verified response repeat invalid: %w", err)
		}
		if source.Origin != origin || repeat.Origin != origin || source.URLSHA256 != repeat.URLSHA256 || source.SHA256 != repeat.SHA256 || source.Status != repeat.Status || source.Truncated || repeat.Truncated {
			return nil, errors.New("verified response metadata mismatch")
		}
		if _, err := s.RawEvidence(ctx, m.RunID, m.SourceEventID); err != nil {
			return nil, err
		}
		if _, err := s.RawEvidence(ctx, m.RunID, m.RepeatEventID); err != nil {
			return nil, err
		}
		m.Status = source.Status
		m.URLSHA256 = source.URLSHA256
		m.BodySHA256 = source.SHA256
		out = append(out, m)
	}
	return out, nil
}

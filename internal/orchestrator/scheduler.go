// Package orchestrator coordinates bounded agent jobs and immutable run grants.
package orchestrator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"shadow/internal/agent"
	"shadow/internal/broker"
	"shadow/internal/config"
	"shadow/internal/policy"
	"shadow/internal/sandbox"
	"shadow/internal/store"
)

var roles = []string{"surface", "source", "verify", "report"}

var roleTask = map[string]string{
	"surface": "Map the authorized origin from available evidence. Use only explicitly granted read action IDs when offered; record observations and uncertainty.",
	"source":  "Review the attached source or local artifacts if present. Use only the network-disabled sandbox. Record evidence references and uncertainty.",
	"verify":  "Assess prior observations. A reproduced HTTP response is only a response observation, not a verified vulnerability. Identify safe validation steps and unresolved hypotheses.",
	"report":  "Summarize supported observations, hypotheses, and limitations. Cite event IDs. Do not claim a security finding was verified without target evidence.",
}

var roleTools = map[string]map[string]bool{
	"surface": {"read_event": true, "load_skill": true, "remember_observation": true, "approved_http_read": true},
	"source":  {"sandbox_command": true, "read_event": true, "load_skill": true, "remember_observation": true},
	"verify":  {"sandbox_command": true, "read_event": true, "load_skill": true, "remember_observation": true},
	"report":  {"read_event": true, "load_skill": true},
}

type Scheduler struct {
	Store         *store.Store
	Route         config.Route
	Key           string
	Workspace     string
	Sandbox       *sandbox.Runner
	Budget        agent.Budget
	Notify        func(agent.Event)
	ApprovedReads *policy.VerifiedRules // optional locally signed exact GET/read grant
}

func (s *Scheduler) Start(ctx context.Context, prompt, target string) (string, error) {
	if s.Store == nil || s.Key == "" || prompt == "" || len(prompt) > 8192 || s.Route.BaseURL == "" || s.Route.Model == "" || s.Route.Protocol != "openai-chat" {
		return "", errors.New("incomplete orchestration input")
	}
	if err := s.Budget.Validate(); err != nil {
		return "", err
	}
	if s.Budget.MaxCostMicroUSD == 0 || !s.Budget.KnownPrice {
		return "", errors.New("orchestration requires a known model price and finite per-agent cost budget")
	}
	u, err := url.Parse(s.Route.BaseURL)
	if err != nil || u == nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Scheme != "https" && !(u.Scheme == "http" && (strings.EqualFold(u.Hostname(), "localhost") || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
		return "", errors.New("provider endpoint is not a valid secret-free HTTPS or local HTTP URL")
	}
	scope, err := policy.FromTarget(target)
	if err != nil {
		return "", err
	}
	var id [12]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	runID := hex.EncodeToString(id[:])
	if s.ApprovedReads != nil {
		if !s.Store.EvidenceKeyReady() {
			return "", errors.New("approved agent reads require an evidence key")
		}
		if s.ApprovedReads.Origin() != scope.Origin || len(s.ApprovedReads.Actions()) == 0 {
			return "", errors.New("approved read origin or actions differ from target")
		}
		for _, action := range s.ApprovedReads.Actions() {
			if action.Method != "GET" || action.Effect != policy.EffectRead {
				return "", errors.New("agent approval permits only exact GET/read actions")
			}
		}
		if err := s.Store.StartApprovedRun(ctx, runID, *s.ApprovedReads); err != nil {
			return "", err
		}
	} else if err := s.Store.StartRun(ctx, runID, scope, nil); err != nil {
		return "", err
	}
	route, err := json.Marshal(s.Route)
	if err != nil {
		return runID, err
	}
	budget, err := json.Marshal(s.Budget)
	if err != nil {
		return runID, err
	}
	if err := s.Store.CreateAgentPlan(ctx, runID, store.PromptDigest(prompt), route, budget, roles); err != nil {
		return runID, err
	}
	if s.Notify != nil {
		s.Notify(agent.Event{Kind: "plan", Text: runID})
	}
	return runID, s.RunPending(ctx, runID, prompt)
}

// RunPending checks the stored prompt and route snapshot. Running jobs are not
// retried. Recovery must first mark them interrupted and an operator must
// explicitly review their possible side effects before retrying them.
func (s *Scheduler) RunPending(ctx context.Context, runID, prompt string) error {
	plan, err := s.Store.AgentPlan(ctx, runID)
	if err != nil {
		return err
	}
	if plan.PromptSHA256 != store.PromptDigest(prompt) {
		return errors.New("task text differs from the original plan")
	}
	var route config.Route
	var budget agent.Budget
	if err := json.Unmarshal(plan.Route, &route); err != nil {
		return err
	}
	if err := json.Unmarshal(plan.Budget, &budget); err != nil {
		return err
	}
	if err := budget.Validate(); err != nil {
		return err
	}
	if budget.MaxCostMicroUSD == 0 || !budget.KnownPrice {
		return errors.New("stored plan lacks a finite cost budget")
	}
	if route != s.Route || budget != s.Budget {
		return errors.New("route or agent budget differs from the immutable plan")
	}
	if s.Key == "" {
		return errors.New("provider key required")
	}
	snapshot, err := s.Store.RunSnapshot(ctx, runID)
	if err != nil {
		return errors.New("orchestration run snapshot unavailable")
	}
	if s.ApprovedReads == nil && len(snapshot.Actions) != 0 {
		return errors.New("orchestration run has unexpected network grants")
	}
	if s.ApprovedReads != nil {
		if !s.Store.EvidenceKeyReady() || !time.Now().Before(s.ApprovedReads.ExpiresAt()) {
			return errors.New("approved agent read key or approval is unavailable")
		}
		if snapshot.Origin != s.ApprovedReads.Origin() || len(snapshot.Actions) != len(s.ApprovedReads.Actions()) {
			return errors.New("orchestration approval differs from run snapshot")
		}
		for _, action := range s.ApprovedReads.Actions() {
			if action.Method != "GET" || action.Effect != policy.EffectRead || !snapshot.AllowsAction(action) {
				return errors.New("orchestration action differs from run approval")
			}
		}
		if id, digest, expires, err := s.Store.RunRuleApproval(ctx, runID); err != nil || id != s.ApprovedReads.ApprovalID() || digest != s.ApprovedReads.RulesSHA256() || !expires.Equal(s.ApprovedReads.ExpiresAt()) {
			return errors.New("orchestration run approval unavailable or changed")
		}
	}
	// Build the gateway before claiming any jobs. A blocked destination or
	// unavailable approval must not start an unrelated provider request.
	var approved *broker.ApprovedReadNetwork
	if s.ApprovedReads != nil {
		approved, err = broker.NewApprovedReadNetwork(ctx, s.Store, runID, *s.ApprovedReads)
		if err != nil {
			return err
		}
	}
	// Independent discovery jobs can run together. Later jobs require both
	// discovery jobs and then verification to have completed successfully.
	for _, wave := range [][]string{{"surface", "source"}, {"verify"}, {"report"}} {
		plan, err = s.Store.AgentPlan(ctx, runID)
		if err != nil {
			return err
		}
		states := map[string]string{}
		for _, job := range plan.Jobs {
			states[job.Role] = job.Status
		}
		if len(states) != len(roles) {
			return errors.New("agent plan role set is incomplete")
		}
		if wave[0] == "verify" && (states["surface"] != "done" || states["source"] != "done") {
			return errors.New("verification waits for both discovery jobs")
		}
		if wave[0] == "report" && states["verify"] != "done" {
			return errors.New("report waits for verification")
		}
		var wg sync.WaitGroup
		errs := make(chan error, len(wave))
		for _, role := range wave {
			if states[role] == "done" {
				continue
			}
			if states[role] != "pending" {
				return fmt.Errorf("agent %s requires outcome review (%s)", role, states[role])
			}
			wg.Add(1)
			go func(role string) {
				defer wg.Done()
				errs <- s.runJob(ctx, runID, role, prompt, snapshot.Origin, approved)
			}(role)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Scheduler) runJob(ctx context.Context, runID, role, prompt, origin string, approved *broker.ApprovedReadNetwork) error {
	plan, err := s.Store.AgentPlan(ctx, runID)
	if err != nil {
		return err
	}
	var initial agent.Checkpoint
	found := false
	for _, job := range plan.Jobs {
		if job.Role == role {
			initial = agent.Checkpoint{Step: job.Step, InputTokens: job.InputTokens, OutputTokens: job.OutputTokens, CostMicroUSD: job.CostMicroUSD, ToolCalls: job.ToolCalls}
			found = true
			break
		}
	}
	if !found {
		return errors.New("agent job not found")
	}
	if err := s.Store.AgentJobTransition(ctx, runID, role, "pending", "running", "claimed", initial.Step, initial.InputTokens, initial.OutputTokens, initial.CostMicroUSD, initial.ToolCalls); err != nil {
		return err
	}
	last := initial
	if role != "surface" {
		approved = nil
	}
	r := agent.Runner{RunID: runID, Role: role, Route: s.Route, Key: s.Key, Workspace: s.Workspace, Store: s.Store, Sandbox: s.Sandbox, Notify: s.Notify, Budget: &s.Budget, AllowedTools: roleTools[role],
		ApprovedReads: approved,
		Initial:       initial,
		Checkpoint: func(ctx context.Context, c agent.Checkpoint) error {
			last = c
			return s.Store.AgentJobTransition(ctx, runID, role, "running", "running", c.Phase, c.Step, c.InputTokens, c.OutputTokens, c.CostMicroUSD, c.ToolCalls)
		},
	}
	_, err = r.Run(ctx, "Role: "+role+". "+roleTask[role]+"\nUser task: "+prompt, origin)
	status, phase := "done", "completed"
	if err != nil {
		status, phase = "interrupted", "outcome_unknown"
	}
	transitionErr := s.Store.AgentJobTransition(context.WithoutCancel(ctx), runID, role, "running", status, phase, last.Step, last.InputTokens, last.OutputTokens, last.CostMicroUSD, last.ToolCalls)
	if transitionErr != nil {
		return fmt.Errorf("agent %s: %v; checkpoint: %w", role, err, transitionErr)
	}
	if err != nil {
		return fmt.Errorf("agent %s interrupted: %w", role, err)
	}
	return nil
}

func (s *Scheduler) Recover(ctx context.Context, runID string) (store.AgentPlan, error) {
	if _, err := s.Store.RecoverAgentPlan(ctx, runID); err != nil {
		return store.AgentPlan{}, err
	}
	return s.Store.AgentPlan(ctx, runID)
}

func (s *Scheduler) RetryInterrupted(ctx context.Context, runID, role, reviewedOutcome string) error {
	return s.Store.RetryInterruptedAgentJob(ctx, runID, role, reviewedOutcome)
}

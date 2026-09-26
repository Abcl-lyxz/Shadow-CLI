package ui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"shadow/internal/agent"
	"shadow/internal/config"
	"shadow/internal/policy"
)

var panes = []string{"log", "board", "trace", "memory", "findings", "budget"}

func sameEndpoint(a, b config.Route) bool {
	return a.Provider != "" && a.Provider == b.Provider && a.BaseURL == b.BaseURL && a.Protocol == b.Protocol
}

func (m *Model) checkModelCapability() error {
	if m.cfg.Route.Model == "" || m.cfg.Route.BaseURL == "" {
		return errors.New("select a provider and model first")
	}
	if m.verifiedToolRoute == m.cfg.Route {
		return nil
	}
	if !m.catalogStale && !m.catalogAt.IsZero() && time.Since(m.catalogAt) <= 7*24*time.Hour {
		if p, ok := m.catalog[m.cfg.Route.Provider]; ok && p.API == m.cfg.Route.BaseURL {
			if model, ok := p.Models[m.cfg.Route.Model]; ok && model.ToolCall {
				return nil
			}
		}
	}
	return errors.New("model tool capability is unverified or catalog is stale; run /models probe before starting")
}

func (m *Model) nextPane() {
	for i, pane := range panes {
		if pane == m.pane {
			m.showPane(panes[(i+1)%len(panes)])
			return
		}
	}
	m.showPane("board")
}

func safeStatus(s string) string {
	if s == "" {
		return "-"
	}
	if len(s) > 40 {
		return "invalid"
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return "invalid"
		}
	}
	return s
}

func (m *Model) showPane(name string) {
	if name == "" {
		name = "log"
	}
	m.pane = name
	m.paneLines = []string{strings.ToUpper(name)}
	if name == "log" {
		return
	}
	if m.store == nil {
		m.paneLines = append(m.paneLines, "Store unavailable.")
		return
	}
	ctx := context.Background()
	if name == "memory" {
		if m.target == "" {
			m.paneLines = append(m.paneLines, "Set /target first.")
			return
		}
		scope, err := policy.FromTarget(m.target)
		if err != nil {
			m.paneLines = append(m.paneLines, "Invalid target.")
			return
		}
		notes, err := m.store.RecallVerifiedResponses(ctx, scope.Origin, 10)
		if err != nil {
			m.paneLines = append(m.paneLines, "Verified memory unavailable: "+err.Error())
			return
		}
		for _, note := range notes {
			m.paneLines = append(m.paneLines, fmt.Sprintf("run %s  source #%d  repeat #%d  response reproduced (not vulnerability verified)", safeStatus(note.RunID), note.SourceEventID, note.RepeatEventID))
		}
		if len(notes) == 0 {
			m.paneLines = append(m.paneLines, "No verified response memory for this origin.")
		}
		return
	}
	runID := m.currentRunID
	if runID == "" {
		ids, err := m.store.AgentPlanIDs(ctx, 1)
		if err == nil && len(ids) > 0 {
			runID = ids[0]
		}
	}
	if runID == "" {
		m.paneLines = append(m.paneLines, "No agent run recorded.")
		return
	}
	m.paneLines = append(m.paneLines, "Run "+safeStatus(runID))
	switch name {
	case "board", "budget":
		plan, err := m.store.AgentPlan(ctx, runID)
		if err != nil {
			m.paneLines = append(m.paneLines, "Plan unavailable: "+err.Error())
			return
		}
		if name == "board" {
			for _, job := range plan.Jobs {
				m.paneLines = append(m.paneLines, fmt.Sprintf("%-9s  %-12s  %-16s  step %d  tools %d", safeStatus(job.Role), safeStatus(job.Status), safeStatus(job.Phase), job.Step, job.ToolCalls))
			}
			return
		}
		var budget agent.Budget
		if err := json.Unmarshal(plan.Budget, &budget); err != nil {
			m.paneLines = append(m.paneLines, "Budget snapshot invalid.")
			return
		}
		var in, out, cost int64
		var tools int
		for _, job := range plan.Jobs {
			in += job.InputTokens
			out += job.OutputTokens
			cost += job.CostMicroUSD
			tools += job.ToolCalls
		}
		m.paneLines = append(m.paneLines,
			fmt.Sprintf("Used: input %d / output %d tokens; tools %d; estimated $%.6f", in, out, tools, float64(cost)/1e6),
			fmt.Sprintf("Per role cap: input %d / output %d tokens; tools %d; estimated $%.6f", budget.MaxInputTokens, budget.MaxOutputTokens, budget.MaxTools, float64(budget.MaxCostMicroUSD)/1e6))
	case "trace":
		events, err := m.store.EventHeads(ctx, runID, 80)
		if err != nil {
			m.paneLines = append(m.paneLines, "Trace unavailable: "+err.Error())
			return
		}
		for _, event := range events {
			m.paneLines = append(m.paneLines, fmt.Sprintf("#%d  %s  %s", event.ID, event.At.Local().Format("15:04:05"), safeStatus(event.Kind)))
		}
		if len(events) == 0 {
			m.paneLines = append(m.paneLines, "No events recorded.")
		}
	case "findings":
		findings, err := m.store.Findings(ctx, runID)
		if err != nil {
			m.paneLines = append(m.paneLines, "Findings unavailable: "+err.Error())
			return
		}
		reviews, err := m.store.FindingReviews(ctx, runID)
		if err != nil {
			m.paneLines = append(m.paneLines, "Reviews unavailable: "+err.Error())
			return
		}
		for _, f := range findings {
			line := fmt.Sprintf("#%d  %s  %s  evidence #%d", f.ID, safeStatus(f.ClaimType), safeStatus(f.Status), f.SourceEventID)
			if review, ok := reviews[f.ID]; ok {
				line += "  review " + safeStatus(review.PoCStatus) + "/" + safeStatus(review.Confidence)
			}
			m.paneLines = append(m.paneLines, line)
		}
		if len(findings) == 0 {
			m.paneLines = append(m.paneLines, "No findings recorded.")
		}
	default:
		m.paneLines = append(m.paneLines, "Unknown view.")
	}
}

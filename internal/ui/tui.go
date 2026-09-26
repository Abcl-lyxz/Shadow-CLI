package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"shadow/internal/agent"
	"shadow/internal/artifact"
	"shadow/internal/catalog"
	"shadow/internal/config"
	"shadow/internal/dashboard"
	"shadow/internal/orchestrator"
	"shadow/internal/policy"
	"shadow/internal/provider"
	"shadow/internal/sandbox"
	"shadow/internal/skills"
	"shadow/internal/store"
)

var urlPattern = regexp.MustCompile(`https?://[^\s<>"]+`)

type eventMsg agent.Event
type catalogMsg struct {
	data  catalog.Catalog
	stale bool
	err   error
}
type doneMsg struct {
	id  string
	err error
}
type modelMsg struct {
	ids   []string
	err   error
	route config.Route
}
type probeMsg struct {
	route config.Route
	ok    bool
	err   error
}

type Model struct {
	cfg               config.Config
	catalog           catalog.Catalog
	endpointModels    map[string]bool
	endpointRoute     config.Route
	verifiedToolRoute config.Route
	catalogStale      bool
	catalogAt         time.Time
	pane              string
	paneLines         []string
	sandbox           *sandbox.Runner
	store             *store.Store
	catalogCache      string
	send              func(tea.Msg)
	lines             []string
	input             []rune
	secret            bool
	pendingID         string
	pendingAPI        string
	target            string
	workspace         string
	dashboardURL      string
	width             int
	height            int
	running           bool
	quit              bool
	cancel            context.CancelFunc
	runDone           chan struct{}
	currentRunID      string
	manualPriceRoute  config.Route
	manualInputPrice  float64
	manualOutputPrice float64
}

func Run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	dir, err := config.Dir()
	if err != nil {
		return err
	}
	days, err := cfg.RetentionDays()
	if err != nil {
		return err
	}
	st, retention, err := openStoreWithRetention(filepath.Join(dir, "shadow.db"), days)
	if err != nil {
		return err
	}
	defer st.Close()
	sb, err := sandbox.New("")
	if err != nil {
		return err
	}
	defer sb.Close()
	dash, dashURL, err := dashboard.Start(st)
	if err != nil {
		return err
	}
	defer dash.Close()
	m := &Model{
		cfg: cfg, sandbox: sb, store: st, catalogCache: filepath.Join(dir, "models-dev.json"), width: 100, height: 30,
		dashboardURL: dashURL,
		lines: []string{
			"Shadow CLI • development build",
			"Use /connect to choose a provider, /models to choose a model, /target URL, then describe a task.",
			"Live web requests and test writes are disabled until the security release gates pass.",
		},
	}
	if retention.Purged > 0 || retention.Blocked > 0 {
		m.lines = append(m.lines, fmt.Sprintf("Retention: %d expired runs removed; %d kept for cleanup or active requests.", retention.Purged, retention.Blocked))
	}
	var program *tea.Program
	m.send = func(msg tea.Msg) { program.Send(msg) }
	program = tea.NewProgram(m)
	_, err = program.Run()
	if m.cancel != nil {
		m.cancel()
	}
	if m.runDone != nil {
		select {
		case <-m.runDone:
		case <-time.After(20 * time.Second):
			return fmt.Errorf("agent shutdown timed out after TUI exit")
		}
	}
	return err
}

func openStore(path string) (*store.Store, error) {
	st, _, err := openStoreWithRetention(path, config.DefaultAutoRetentionDays)
	return st, err
}

func openStoreWithRetention(path string, days int) (*store.Store, store.RetentionResult, error) {
	var retention store.RetentionResult
	st, err := store.Open(path)
	if err != nil {
		return nil, retention, err
	}
	hasEvidence, err := st.HasEvidence(context.Background())
	if err != nil {
		st.Close()
		return nil, retention, err
	}
	evidenceKey, err := config.EvidenceKey(!hasEvidence)
	if err != nil {
		st.Close()
		return nil, retention, err
	}
	if err := st.ConfigureEvidenceKey(context.Background(), evidenceKey); err != nil {
		st.Close()
		return nil, retention, err
	}
	ledger, head := store.DefaultProvenancePaths(path)
	if err := st.EnableProvenance(context.Background(), ledger, head); err != nil {
		st.Close()
		return nil, retention, err
	}
	retention, err = st.PruneExpired(context.Background(), time.Now(), days)
	if err != nil {
		st.Close()
		return nil, retention, err
	}
	return st, retention, nil
}

func (m *Model) Init() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		data, stale, err := catalog.Load(ctx, nil, m.catalogCache)
		return catalogMsg{data: data, stale: stale, err: err}
	}
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = v.Width, v.Height
	case catalogMsg:
		if v.err != nil {
			m.add("Catalog unavailable: " + v.err.Error() + ". Custom /connect remains available.")
		} else {
			m.catalog = v.data
			m.catalogStale = v.stale
			m.catalogAt = time.Now()
			if v.stale {
				if info, err := os.Stat(m.catalogCache); err == nil {
					m.catalogAt = info.ModTime()
				}
			}
			source := "live"
			if v.stale {
				source = "cached; confirm endpoint models with /models refresh"
			}
			m.add(fmt.Sprintf("Provider catalog loaded: %d providers (%s).", len(v.data), source))
		}
	case eventMsg:
		if v.Kind == "plan" {
			m.currentRunID = v.Text
		}
		label := v.Kind
		if v.Role != "" {
			label = v.Role + "/" + label
		}
		m.add(fmt.Sprintf("[%s] %s", label, v.Text))
		if m.pane != "" && m.pane != "log" {
			m.showPane(m.pane)
		}
	case doneMsg:
		if v.id != "" {
			m.currentRunID = v.id
		}
		m.running = false
		m.cancel = nil
		if v.err != nil {
			m.add("Run " + v.id + " stopped: " + v.err.Error())
		} else {
			m.add("Run " + v.id + " complete.")
		}
		if m.pane != "" && m.pane != "log" {
			m.showPane(m.pane)
		}
	case modelMsg:
		if v.route != m.cfg.Route {
			break
		}
		if v.err != nil {
			m.add("Model discovery failed: " + v.err.Error())
		} else {
			m.endpointModels = make(map[string]bool, len(v.ids))
			m.endpointRoute = v.route
			for _, id := range v.ids {
				m.endpointModels[id] = true
			}
			m.add("Endpoint models: " + strings.Join(limitStrings(v.ids, 20), ", "))
		}
	case probeMsg:
		if v.route != m.cfg.Route {
			break
		}
		if v.err != nil {
			m.add("Model tool capability probe request failed: " + v.err.Error())
		} else if !v.ok {
			m.add("Model response lacked a function tool call or usage report; this route cannot start an agent run.")
		} else {
			m.verifiedToolRoute = v.route
			m.add("Model tool capability and usage reporting verified for this route.")
		}
	case tea.KeyPressMsg:
		switch v.String() {
		case "ctrl+c":
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		case "tab":
			if !m.secret {
				m.nextPane()
				return m, nil
			}
		case "ctrl+r":
			if !m.secret {
				m.showPane(m.pane)
				return m, nil
			}
		case "esc":
			if !m.secret {
				m.showPane("log")
				return m, nil
			}
		case "ctrl+p":
			if !m.secret {
				m.handle("/pause")
				return m, nil
			}
		case "enter":
			input := strings.TrimSpace(string(m.input))
			m.input = nil
			if m.secret {
				m.secret = false
				if err := config.SetKey(m.pendingID, input); err != nil {
					m.add("Credential storage failed: " + err.Error())
				} else {
					m.cfg.Route = config.Route{Provider: m.pendingID, BaseURL: m.pendingAPI, Protocol: "openai-chat"}
					if err := config.Save(m.cfg); err != nil {
						m.add("Config save failed: " + err.Error())
					} else {
						m.add("Connected " + m.pendingID + ". Choose a model with /models <id>.")
					}
				}
				m.pendingID, m.pendingAPI = "", ""
				return m, nil
			}
			if input != "" {
				m.handle(input)
				if m.quit {
					if m.cancel != nil {
						m.cancel()
					}
					return m, tea.Quit
				}
			}
		case "backspace":
			if len(m.input) > 0 {
				m.input = m.input[:len(m.input)-1]
			}
		default:
			key := v.Key()
			if len(key.Text) > 0 {
				m.input = append(m.input, []rune(key.Text)...)
			}
		}
	}
	return m, nil
}

func (m *Model) handle(input string) {
	if strings.HasPrefix(input, "/") {
		fields := strings.Fields(input)
		switch fields[0] {
		case "/help":
			m.add("/connect [provider [base-url]]  /models [id|refresh|probe]  /price INPUT OUTPUT  /target URL  /attach DIR  /artifact FILE  /scope  /board  /trace  /memory  /findings  /budget  /skills  /agents [run-id]  /recover ID  /review ID ROLE OUTCOME  /resume ID original-task  /dashboard  /pause  /stop  /quit")
			m.add("Tab: next view; Ctrl+R: refresh view; Esc: log; Ctrl+P: pause. Paused jobs require review before /resume.")
		case "/connect":
			if len(fields) == 1 {
				m.add("Providers: " + joinProviders(m.catalog.Search("", 18)))
				m.add("Use /connect <provider>. For custom providers: /connect <id> <https-base-url>.")
				return
			}
			id := fields[1]
			api := ""
			if p, ok := m.catalog[id]; ok {
				api = p.API
				if !strings.Contains(p.NPM, "openai") {
					m.add("This provider uses a protocol adapter that is not implemented yet.")
					return
				}
			}
			if len(fields) > 2 {
				api = fields[2]
			}
			if api == "" {
				m.add("This provider has no catalog API URL. Use /connect " + id + " <https-base-url>.")
				return
			}
			m.pendingID, m.pendingAPI, m.secret = id, api, true
			m.endpointModels = nil
			m.verifiedToolRoute = config.Route{}
			m.add("Enter API key for " + id + " (input hidden):")
		case "/models":
			if len(fields) > 1 && fields[1] == "probe" {
				if m.cfg.Route.Model == "" {
					m.add("Select a model before probing its tool capability.")
					return
				}
				key, err := config.Key(m.cfg.Route.Provider)
				if err != nil {
					m.add("Provider key unavailable: " + err.Error())
					return
				}
				route := m.cfg.Route
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					tool := provider.Tool{Type: "function"}
					tool.Function.Name = "shadow_capability_probe"
					tool.Function.Description = "Return a fixed capability acknowledgement"
					tool.Function.Parameters = json.RawMessage(`{"type":"object","properties":{}}`)
					msg, usage, err := (provider.Client{BaseURL: route.BaseURL, Key: key}).ChatWithUsageLimit(ctx, route.Model, []provider.Message{{Role: "user", Content: "Call shadow_capability_probe with {}. No target data is involved."}}, []provider.Tool{tool}, 64)
					ok := usage.Known && len(msg.ToolCalls) == 1 && msg.ToolCalls[0].Type == "function" && msg.ToolCalls[0].Function.Name == tool.Function.Name && json.Valid([]byte(msg.ToolCalls[0].Function.Arguments))
					m.send(probeMsg{route: route, ok: ok, err: err})
				}()
				m.add("Checking model tool calls and usage reporting...")
				return
			}
			if len(fields) > 1 && fields[1] == "refresh" {
				key, err := config.Key(m.cfg.Route.Provider)
				if err != nil {
					m.add("No key in OS keyring: " + err.Error())
					return
				}
				route := m.cfg.Route
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					ids, err := (provider.Client{BaseURL: route.BaseURL, Key: key}).Models(ctx)
					m.send(modelMsg{ids: ids, err: err, route: route})
				}()
				return
			}
			if len(fields) > 1 {
				id := fields[1]
				if p, ok := m.catalog[m.cfg.Route.Provider]; ok {
					if _, exists := p.Models[id]; !exists && !(sameEndpoint(m.endpointRoute, m.cfg.Route) && m.endpointModels[id]) {
						m.add("Model is not in catalog; run /models refresh to confirm endpoint model IDs.")
						return
					}
				}
				m.cfg.Route.Model = id
				m.verifiedToolRoute = config.Route{}
				m.manualPriceRoute = config.Route{}
				if err := config.Save(m.cfg); err != nil {
					m.add(err.Error())
				} else {
					m.add("Selected model: " + id)
				}
				return
			}
			if p, ok := m.catalog[m.cfg.Route.Provider]; ok {
				m.add("Tool-capable models: " + strings.Join(limitStrings(p.ToolModels(), 25), ", "))
			} else {
				m.add("Run /models refresh, then /models <id>.")
			}
		case "/price":
			if len(fields) != 3 || m.cfg.Route.Model == "" {
				m.add("Usage: /price <input-USD-per-million> <output-USD-per-million> after /models.")
				return
			}
			in, inErr := strconv.ParseFloat(fields[1], 64)
			out, outErr := strconv.ParseFloat(fields[2], 64)
			if inErr != nil || outErr != nil || math.IsNaN(in) || math.IsNaN(out) || math.IsInf(in, 0) || math.IsInf(out, 0) || in < 0 || out < 0 || in > 1000 || out > 1000 {
				m.add("Prices must be numbers from 0 to 1000 USD per million tokens.")
				return
			}
			m.manualPriceRoute, m.manualInputPrice, m.manualOutputPrice = m.cfg.Route, in, out
			m.add("Model prices set for this session. Confirm them with the provider before running a paid model.")
		case "/target":
			if len(fields) < 2 {
				m.add("Usage: /target https://example.com")
				return
			}
			scope, err := policy.FromTarget(fields[1])
			if err != nil {
				m.add(err.Error())
			} else {
				m.target = fields[1]
				m.add("Target: " + m.target + " | exact origin: " + scope.Origin)
			}
		case "/scope":
			if m.target == "" {
				m.add("No target set.")
			} else {
				scope, _ := policy.FromTarget(m.target)
				m.add("Active scope: " + scope.Origin + " (no subdomains or third-party redirects)")
			}
		case "/board", "/trace", "/memory", "/findings", "/budget":
			m.showPane(strings.TrimPrefix(fields[0], "/"))
		case "/skills":
			all, err := skills.List()
			if err != nil {
				m.add("Skills unavailable: " + err.Error())
				return
			}
			for _, skill := range all {
				m.add(skill.Name + " — " + skill.Description)
			}
		case "/attach":
			if len(fields) < 2 {
				m.add("Usage: /attach <existing-directory>")
				return
			}
			path, err := filepath.Abs(strings.Join(fields[1:], " "))
			if err != nil {
				m.add(err.Error())
				return
			}
			stat, err := os.Stat(path)
			if err != nil || !stat.IsDir() {
				m.add("Attachment must be an existing directory.")
				return
			}
			if filepath.Dir(path) == path {
				m.add("A filesystem root cannot be attached.")
				return
			}
			m.workspace = path
			m.add("Attached read-only: " + path)
		case "/artifact":
			rel := strings.TrimSpace(strings.TrimPrefix(input, "/artifact"))
			if m.workspace == "" || rel == "" {
				m.add("Attach a directory, then use /artifact <relative-file>.")
				return
			}
			if filepath.IsAbs(rel) {
				m.add("Artifact path must be relative to the attached directory.")
				return
			}
			root, err := filepath.EvalSymlinks(m.workspace)
			if err != nil {
				m.add("Attached directory unavailable.")
				return
			}
			path, err := filepath.EvalSymlinks(filepath.Join(root, rel))
			if err != nil {
				m.add("Artifact file unavailable.")
				return
			}
			inside, err := filepath.Rel(root, path)
			if err != nil || inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) || filepath.IsAbs(inside) {
				m.add("Artifact escapes the attached directory.")
				return
			}
			result, err := artifact.Inspect(path)
			if err != nil {
				m.add("Artifact inspection failed: " + err.Error())
				return
			}
			m.add(fmt.Sprintf("Static %s: %d bytes; SHA-256 %s; arch %s; entries %d", result.Kind, result.Bytes, result.SHA256, valueOr(result.Architecture, "n/a"), result.Entries))
			for _, property := range result.Properties {
				m.add("  " + property.Name + ": " + property.Value)
			}
			m.add("Static metadata only; no vulnerability or runtime impact has been verified.")
		case "/agents":
			id := m.currentRunID
			if len(fields) > 1 {
				id = fields[1]
			}
			if id == "" {
				ids, err := m.store.AgentPlanIDs(context.Background(), 10)
				if err != nil {
					m.add("Agent plans unavailable: " + err.Error())
				} else if len(ids) == 0 {
					m.add("No agent plans recorded.")
				} else {
					m.add("Recent agent plans: " + strings.Join(ids, ", ") + ". Use /agents <run-id> for details.")
				}
				return
			}
			plan, err := m.store.AgentPlan(context.Background(), id)
			if err != nil {
				m.add("Agent plan unavailable: " + err.Error())
				return
			}
			m.add("Plan " + id + " (scope and task remain bound to the original run):")
			for _, job := range plan.Jobs {
				m.add(fmt.Sprintf("  %s: %s / %s; step %d; in %d, out %d tokens; cost %.6f USD; tools %d", job.Role, job.Status, job.Phase, job.Step, job.InputTokens, job.OutputTokens, float64(job.CostMicroUSD)/1e6, job.ToolCalls))
			}
		case "/recover":
			if len(fields) != 2 || m.running {
				m.add("Usage: /recover <run-id> when no run is active.")
				return
			}
			count, err := m.store.RecoverAgentPlan(context.Background(), fields[1])
			if err != nil {
				m.add("Recovery failed: " + err.Error())
			} else {
				m.add(fmt.Sprintf("Recovered plan %s: %d in-progress jobs marked outcome_unknown. Review before retry.", fields[1], count))
			}
		case "/review":
			if len(fields) != 4 || m.running {
				m.add("Usage: /review <run-id> <role> <no_side_effect|side_effect_resolved> when no run is active.")
				return
			}
			if err := m.store.RetryInterruptedAgentJob(context.Background(), fields[1], fields[2], fields[3]); err != nil {
				m.add("Review rejected: " + err.Error())
			} else {
				m.add("Reviewed job returned to pending. Use /resume with the original task text.")
			}
		case "/resume":
			runID, prompt, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(input, "/resume")), " ")
			prompt = strings.TrimSpace(prompt)
			if !ok || runID == "" || prompt == "" || m.running {
				m.add("Usage: /resume <run-id> <original task text> when no run is active.")
				return
			}
			key, err := config.Key(m.cfg.Route.Provider)
			if err != nil {
				m.add("Provider key unavailable: " + err.Error())
				return
			}
			plan, err := m.store.AgentPlan(context.Background(), runID)
			if err != nil {
				m.add("Agent plan unavailable: " + err.Error())
				return
			}
			var budget agent.Budget
			if err := json.Unmarshal(plan.Budget, &budget); err != nil {
				m.add("Stored budget invalid: " + err.Error())
				return
			}
			if err := m.checkModelCapability(); err != nil {
				m.add(err.Error())
				return
			}
			m.startAgentResume(runID, prompt, key, budget)
		case "/dashboard":
			m.add("Local evidence dashboard: " + m.dashboardURL)
		case "/pause", "/stop":
			if m.cancel != nil {
				m.cancel()
				m.add("Cancelling current run; in-progress jobs may have unknown outcomes. Use /recover, /review, then /resume with the original task.")
			}
		case "/quit":
			m.quit = true
		default:
			m.add("Unknown command. Use /help.")
		}
		return
	}
	if m.running {
		m.add("A run is already active. Use /stop first.")
		return
	}
	target := m.target
	if match := urlPattern.FindString(input); match != "" {
		target = strings.TrimRight(match, ".,;)")
	}
	if target == "" {
		m.add("Set a target with /target URL or include an HTTP(S) URL in your instruction.")
		return
	}
	scope, err := policy.FromTarget(target)
	if err != nil {
		m.add(err.Error())
		return
	}
	key, err := config.Key(m.cfg.Route.Provider)
	if err != nil {
		m.add("Connect a provider first: " + err.Error())
		return
	}
	budget, err := m.agentBudget()
	if err != nil {
		m.add(err.Error())
		return
	}
	if err := m.checkModelCapability(); err != nil {
		m.add(err.Error())
		return
	}
	m.target = target
	m.add("You: " + input)
	m.add("Starting four bounded agent roles within " + scope.Origin + ". Network tools are disabled in this development build.")
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel, m.running = cancel, true
	route, workspace, st, sb := m.cfg.Route, m.workspace, m.store, m.sandbox
	done := make(chan struct{})
	m.runDone = done
	go func() {
		s := orchestrator.Scheduler{Route: route, Key: key, Workspace: workspace, Store: st, Sandbox: sb, Budget: budget,
			Notify: func(e agent.Event) { m.send(eventMsg(e)) }}
		id, err := s.Start(ctx, input, target)
		close(done)
		m.send(doneMsg{id, err})
	}()
}

func (m *Model) agentBudget() (agent.Budget, error) {
	budget := agent.Budget{MaxSteps: 4, MaxTools: 8, MaxInputTokens: 120000, MaxOutputTokens: 4000, MaxContextBytes: 32 << 10, MaxCostMicroUSD: 1000000}
	var input, output float64
	if m.manualPriceRoute == m.cfg.Route && m.manualPriceRoute.Model != "" {
		input, output = m.manualInputPrice, m.manualOutputPrice
		budget.KnownPrice = true
	} else if p, ok := m.catalog[m.cfg.Route.Provider]; ok && p.API == m.cfg.Route.BaseURL && !m.catalogStale && (m.catalogAt.IsZero() || time.Since(m.catalogAt) <= 7*24*time.Hour) {
		if model, ok := p.Models[m.cfg.Route.Model]; ok && model.Cost != nil {
			input, output = model.Cost.Input, model.Cost.Output
			budget.KnownPrice = true
		}
	}
	if !budget.KnownPrice || math.IsNaN(input) || math.IsNaN(output) || math.IsInf(input, 0) || math.IsInf(output, 0) || input < 0 || output < 0 || input > 1000 || output > 1000 {
		return budget, fmt.Errorf("model prices are unavailable; use /price INPUT OUTPUT (USD per million tokens) to enable the cost cap")
	}
	budget.InputPriceMicroUSDPerMillion = int64(input*1e6 + 0.5)
	budget.OutputPriceMicroUSDPerMillion = int64(output*1e6 + 0.5)
	return budget, nil
}

func (m *Model) startAgentResume(runID, prompt, key string, budget agent.Budget) {
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel, m.running = cancel, true
	route, workspace, st, sb := m.cfg.Route, m.workspace, m.store, m.sandbox
	done := make(chan struct{})
	m.runDone = done
	go func() {
		s := orchestrator.Scheduler{Route: route, Key: key, Workspace: workspace, Store: st, Sandbox: sb, Budget: budget, Notify: func(e agent.Event) { m.send(eventMsg(e)) }}
		err := s.RunPending(ctx, runID, prompt)
		close(done)
		m.send(doneMsg{runID, err})
	}()
}

func (m *Model) add(line string) {
	for _, piece := range strings.Split(line, "\n") {
		m.lines = append(m.lines, terminalText(piece))
	}
	if len(m.lines) > 400 {
		m.lines = m.lines[len(m.lines)-400:]
	}
}

func terminalText(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if r < 32 || r == 127 || r >= 0x80 && r <= 0x9f {
			return -1
		}
		return r
	}, s)
}

func (m *Model) View() tea.View {
	width := m.width
	if width < 20 {
		width = 20
	}
	height := m.height
	if height < 7 {
		height = 7
	}
	header := clip(terminalText(fmt.Sprintf(" SHADOW  │  %s  │  %s  │  %s ", valueOr(m.cfg.Route.Provider, "no provider"), valueOr(m.cfg.Route.Model, "no model"), valueOr(m.target, "no target"))), width)
	var b strings.Builder
	b.WriteString("\x1b[1;38;5;45m" + header + "\x1b[0m\n")
	b.WriteString(strings.Repeat("─", width) + "\n")
	visible := height - 5
	display := m.lines
	if m.pane != "" && m.pane != "log" {
		display = m.paneLines
	}
	start := len(display) - visible
	if start < 0 {
		start = 0
	}
	panel := width >= 100
	leftWidth := width
	if panel {
		leftWidth = width - 32
	}
	side := []string{
		"  STATUS",
		"",
		"  Agent       " + map[bool]string{true: "RUNNING", false: "IDLE"}[m.running],
		"  Provider    " + valueOr(m.cfg.Route.Provider, "none"),
		"  Model       " + valueOr(m.cfg.Route.Model, "none"),
		"",
		"  TARGET",
		"  " + valueOr(m.target, "not set"),
		"",
		"  WORKSPACE",
		"  " + valueOr(m.workspace, "none"),
		"",
		"  SANDBOX",
		"  Docker · network off",
		"  Root FS · read-only",
		"",
		"  VIEW " + strings.ToUpper(valueOr(m.pane, "log")),
		"  Tab       next",
		"  Ctrl+R    refresh",
		"  Esc       log",
		"  Ctrl+P    pause",
	}
	for i := 0; i < visible; i++ {
		line := ""
		if start+i < len(display) {
			line = terminalText(display[start+i])
		}
		if panel {
			left := clip(line, leftWidth-1)
			b.WriteString(left + strings.Repeat(" ", max(0, leftWidth-runeLen(left))) + "│")
			if i < len(side) {
				b.WriteString(clip(terminalText(side[i]), 30))
			}
		} else {
			b.WriteString(clip(line, width))
		}
		b.WriteString("\n")
	}
	b.WriteString(strings.Repeat("─", width) + "\n")
	prompt := string(m.input)
	if m.secret {
		prompt = strings.Repeat("•", len(m.input))
	}
	b.WriteString(clip(" ❯ "+terminalText(prompt)+"█", width) + "\n")
	b.WriteString(clip(" /help  •  Tab views  •  Ctrl+R refresh  •  Enter send  •  Ctrl+C quit", width))
	return tea.NewView(b.String())
}

func clip(s string, width int) string {
	if width <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= width {
		return s
	}
	return string(r[:width-1]) + "…"
}

func runeLen(s string) int { return len([]rune(s)) }

func joinProviders(ps []catalog.Provider) string {
	ids := make([]string, 0, len(ps))
	for _, p := range ps {
		ids = append(ids, p.ID)
	}
	return strings.Join(ids, ", ")
}

func limitStrings(items []string, max int) []string {
	if len(items) > max {
		return append(items[:max], "…")
	}
	return items
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

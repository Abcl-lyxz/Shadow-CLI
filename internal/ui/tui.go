package ui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"shadow/internal/agent"
	"shadow/internal/catalog"
	"shadow/internal/config"
	"shadow/internal/dashboard"
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
	ids []string
	err error
}

type Model struct {
	cfg            config.Config
	catalog        catalog.Catalog
	endpointModels map[string]bool
	sandbox        *sandbox.Runner
	store          *store.Store
	catalogCache   string
	send           func(tea.Msg)
	lines          []string
	input          []rune
	secret         bool
	pendingID      string
	pendingAPI     string
	target         string
	workspace      string
	dashboardURL   string
	width          int
	height         int
	running        bool
	quit           bool
	cancel         context.CancelFunc
	runDone        chan struct{}
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
	st, err := openStore(filepath.Join(dir, "shadow.db"))
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
	st, err := store.Open(path)
	if err != nil {
		return nil, err
	}
	hasEvidence, err := st.HasEvidence(context.Background())
	if err != nil {
		st.Close()
		return nil, err
	}
	evidenceKey, err := config.EvidenceKey(!hasEvidence)
	if err != nil {
		st.Close()
		return nil, err
	}
	if err := st.ConfigureEvidenceKey(context.Background(), evidenceKey); err != nil {
		st.Close()
		return nil, err
	}
	return st, nil
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
			source := "live"
			if v.stale {
				source = "cached; confirm endpoint models with /models refresh"
			}
			m.add(fmt.Sprintf("Provider catalog loaded: %d providers (%s).", len(v.data), source))
		}
	case eventMsg:
		m.add(fmt.Sprintf("[%s] %s", v.Kind, v.Text))
	case doneMsg:
		m.running = false
		m.cancel = nil
		if v.err != nil {
			m.add("Run " + v.id + " stopped: " + v.err.Error())
		} else {
			m.add("Run " + v.id + " complete.")
		}
	case modelMsg:
		if v.err != nil {
			m.add("Model discovery failed: " + v.err.Error())
		} else {
			m.endpointModels = make(map[string]bool, len(v.ids))
			for _, id := range v.ids {
				m.endpointModels[id] = true
			}
			m.add("Endpoint models: " + strings.Join(limitStrings(v.ids, 20), ", "))
		}
	case tea.KeyPressMsg:
		switch v.String() {
		case "ctrl+c":
			if m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
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
			m.add("/connect [provider [base-url]]  /models [id|refresh]  /target URL  /attach DIR  /scope  /memory  /skills  /agents  /dashboard  /stop  /quit")
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
			m.add("Enter API key for " + id + " (input hidden):")
		case "/models":
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
					m.send(modelMsg{ids, err})
				}()
				return
			}
			if len(fields) > 1 {
				id := fields[1]
				if p, ok := m.catalog[m.cfg.Route.Provider]; ok {
					if _, exists := p.Models[id]; !exists && !m.endpointModels[id] {
						m.add("Model is not in catalog; run /models refresh to confirm endpoint model IDs.")
						return
					}
				}
				m.cfg.Route.Model = id
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
		case "/memory":
			if m.target == "" {
				m.add("No target set.")
				return
			}
			scope, _ := policy.FromTarget(m.target)
			notes, err := m.store.Recall(context.Background(), scope.Origin, 10)
			if err != nil {
				m.add("Memory unavailable: " + err.Error())
				return
			}
			if len(notes) == 0 {
				m.add("No notes for this target origin.")
			}
			for _, note := range notes {
				m.add(fmt.Sprintf("[%s · event %d] %s", note.Topic, note.SourceEventID, note.Summary))
			}
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
		case "/agents":
			if m.running {
				m.add("One analysis agent active. Multi-agent scheduler is a release gate.")
			} else {
				m.add("No agent active.")
			}
		case "/dashboard":
			m.add("Local evidence dashboard: " + m.dashboardURL)
		case "/pause", "/stop":
			if m.cancel != nil {
				m.cancel()
				m.add("Stopping current run.")
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
	m.target = target
	m.add("You: " + input)
	m.add("Starting analysis within " + scope.Origin + ". Network tools are disabled in this development build.")
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel, m.running = cancel, true
	route, workspace, st, sb := m.cfg.Route, m.workspace, m.store, m.sandbox
	done := make(chan struct{})
	m.runDone = done
	go func() {
		r := agent.Runner{Route: route, Key: key, Workspace: workspace, Store: st, Sandbox: sb,
			Notify: func(e agent.Event) { m.send(eventMsg(e)) }}
		id, err := r.Run(ctx, input, target)
		close(done)
		m.send(doneMsg{id, err})
	}()
}

func (m *Model) add(line string) {
	for _, piece := range strings.Split(line, "\n") {
		m.lines = append(m.lines, piece)
	}
	if len(m.lines) > 400 {
		m.lines = m.lines[len(m.lines)-400:]
	}
}

func (m *Model) View() tea.View {
	width := m.width
	if width < 60 {
		width = 60
	}
	height := m.height
	if height < 15 {
		height = 15
	}
	header := clip(fmt.Sprintf(" SHADOW  │  %s  │  %s  │  %s ", valueOr(m.cfg.Route.Provider, "no provider"), valueOr(m.cfg.Route.Model, "no model"), valueOr(m.target, "no target")), width)
	var b strings.Builder
	b.WriteString("\x1b[1;38;5;45m" + header + "\x1b[0m\n")
	b.WriteString(strings.Repeat("─", width) + "\n")
	visible := height - 5
	start := len(m.lines) - visible
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
		"  COMMANDS",
		"  /connect  /models",
		"  /target   /attach",
		"  /memory   /agents",
		"  /dashboard /stop",
	}
	for i := 0; i < visible; i++ {
		line := ""
		if start+i < len(m.lines) {
			line = m.lines[start+i]
		}
		if panel {
			left := clip(line, leftWidth-1)
			b.WriteString(left + strings.Repeat(" ", max(0, leftWidth-runeLen(left))) + "│")
			if i < len(side) {
				b.WriteString(clip(side[i], 30))
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
	b.WriteString(" ❯ " + prompt + "█\n")
	b.WriteString(" /help  •  Enter send  •  Ctrl+C quit")
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

package policy

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Effect is assigned by trusted runtime configuration, never by a model tool call.
type Effect string

const (
	EffectRead      Effect = "read"
	EffectAuth      Effect = "authentication"
	EffectTestWrite Effect = "test_write"
	EffectBlocked   Effect = "blocked"
)

// ActionRule describes one exact request. A test write must name its own
// disposable resource and an exact cleanup request before it can be planned.
type ActionRule struct {
	URL           string `json:"url"`
	Method        string `json:"method"`
	Effect        Effect `json:"effect"`
	Resource      string `json:"resource,omitempty"`
	CleanupURL    string `json:"cleanup_url,omitempty"`
	CleanupMethod string `json:"cleanup_method,omitempty"`
}

type ActionDecision struct {
	Allowed bool
	Reason  string
	Rule    ActionRule
}

type ActionPolicy struct {
	scope Scope
	rules map[string]ActionRule
}

var resourceName = regexp.MustCompile(`^shadow_[a-z0-9][a-z0-9_-]{0,55}$`)

func actionURL(scope Scope, raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.RawFragment != "" || !scope.Allows(raw) {
		return "", errors.New("action URL must be an exact in-scope HTTP URL without a fragment")
	}
	return u.String(), nil
}

func actionKey(method, raw string) string { return method + " " + raw }

// NewActionPolicy accepts only host-owned rules. Supplying a rule is an
// authorization decision; unlisted requests fail closed regardless of method.
func NewActionPolicy(scope Scope, rules []ActionRule) (*ActionPolicy, error) {
	if _, err := actionURL(scope, scope.Origin); err != nil {
		return nil, errors.New("invalid action scope")
	}
	p := &ActionPolicy{scope: scope, rules: make(map[string]ActionRule, len(rules))}
	for _, rule := range rules {
		raw, err := actionURL(scope, rule.URL)
		if err != nil || raw != rule.URL {
			return nil, errors.New("invalid action rule URL")
		}
		if rule.Method != strings.ToUpper(rule.Method) || rule.Method == "" {
			return nil, errors.New("action method must be uppercase")
		}
		switch rule.Effect {
		case EffectRead:
			if rule.Method != http.MethodGet && rule.Method != http.MethodHead {
				return nil, errors.New("read rule requires GET or HEAD")
			}
		case EffectAuth:
			if rule.Method != http.MethodPost {
				return nil, errors.New("authentication rule requires POST")
			}
			loginURL, err := url.Parse(rule.URL)
			if err != nil || loginURL.RawQuery != "" {
				return nil, errors.New("authentication URL cannot carry query credentials")
			}
		case EffectTestWrite:
			if rule.Method != http.MethodPost && rule.Method != http.MethodPut && rule.Method != http.MethodPatch {
				return nil, errors.New("test write method is unsupported")
			}
			cleanup, err := actionURL(scope, rule.CleanupURL)
			if err != nil || cleanup != rule.CleanupURL || rule.CleanupMethod != http.MethodDelete || !resourceName.MatchString(rule.Resource) {
				return nil, errors.New("test write requires a named resource and exact in-scope DELETE cleanup")
			}
		case EffectBlocked:
		default:
			return nil, errors.New("unknown action effect")
		}
		if rule.Effect != EffectTestWrite && (rule.Resource != "" || rule.CleanupURL != "" || rule.CleanupMethod != "") {
			return nil, errors.New("cleanup fields are only valid for test writes")
		}
		key := actionKey(rule.Method, rule.URL)
		if _, exists := p.rules[key]; exists {
			return nil, errors.New("duplicate action rule")
		}
		p.rules[key] = rule
	}
	return p, nil
}

func (p *ActionPolicy) Classify(method, raw string) ActionDecision {
	if p == nil || method != strings.ToUpper(method) {
		return ActionDecision{Reason: "invalid action method or policy"}
	}
	canonical, err := actionURL(p.scope, raw)
	if err != nil || canonical != raw {
		return ActionDecision{Reason: "request is outside exact scope or malformed"}
	}
	rule, ok := p.rules[actionKey(method, raw)]
	if !ok {
		return ActionDecision{Reason: "request has no trusted action rule"}
	}
	if rule.Effect == EffectBlocked {
		return ActionDecision{Reason: "action is prohibited", Rule: rule}
	}
	return ActionDecision{Allowed: true, Rule: rule}
}

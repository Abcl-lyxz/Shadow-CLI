package broker

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"

	"shadow/internal/config"
	"shadow/internal/policy"
	"shadow/internal/store"
)

// fixtureAuthenticator owns one volatile session for one run and auth action.
// Constructing a new adapter after restart never restores or replays a login.
type fixtureAuthenticator struct {
	store    *store.Store
	snapshot store.RunSnapshot
	rule     policy.ActionRule
	reader   *fixtureDispatcher
	fetcher  *fetcher
	mu       sync.Mutex
	cookie   string
	expires  time.Time
}

func newFixtureAuthenticator(ctx context.Context, st *store.Store, snapshot store.RunSnapshot, rule policy.ActionRule, reader *fixtureDispatcher, opts Options) (*fixtureAuthenticator, error) {
	if reader == nil || !reflect.DeepEqual(reader.snapshot, snapshot) || rule.Effect != policy.EffectAuth || rule.Method != http.MethodPost || !snapshot.AllowsAction(rule) || !opts.AllowLoopback {
		return nil, errors.New("fixture authentication requires a snapshotted loopback action and read grant")
	}
	scope, err := policy.FromTarget(snapshot.Origin)
	if err != nil || scope.Origin != snapshot.Origin {
		return nil, errors.New("invalid fixture authentication origin")
	}
	opts.allowedURLs = []string{rule.URL}
	f, err := newFetcher(ctx, scope, opts)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(f.ipString()); ip == nil || !ip.IsLoopback() || !ip.Equal(net.ParseIP(reader.fetcher.ipString())) {
		return nil, errors.New("fixture authentication destination differs from read destination")
	}
	f.authOnly = true
	bindFixtureBudget(f, st, snapshot.RunID, false)
	a := &fixtureAuthenticator{store: st, snapshot: snapshot, rule: rule, reader: reader, fetcher: f}
	f.guard = a.authorize
	f.deny = a.deny
	return a, nil
}

func (a *fixtureAuthenticator) current(ctx context.Context) (store.RunSnapshot, error) {
	current, err := a.store.RunSnapshot(ctx, a.snapshot.RunID)
	if err != nil || !reflect.DeepEqual(current, a.snapshot) {
		return store.RunSnapshot{}, errors.New("fixture authentication run snapshot unavailable or changed")
	}
	return current, nil
}

func (a *fixtureAuthenticator) deny(ctx context.Context, raw string) error {
	current, err := a.current(ctx)
	if err != nil {
		return err
	}
	return a.store.RecordFixtureNetworkDecision(ctx, current, http.MethodPost, raw, false)
}

func (a *fixtureAuthenticator) authorize(ctx context.Context, raw string) error {
	current, err := a.current(ctx)
	if err != nil {
		return err
	}
	if raw != a.rule.URL || !current.AllowsAction(a.rule) {
		if err := a.store.RecordFixtureNetworkDecision(ctx, current, http.MethodPost, raw, false); err != nil {
			return err
		}
		return errors.New("fixture authentication route denied")
	}
	return a.store.RecordFixtureAuthDecision(ctx, current, raw)
}

func (a *fixtureAuthenticator) authenticate(ctx context.Context, actionID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cookie, a.expires = "", time.Time{}
	if _, err := a.current(ctx); err != nil {
		return err
	}
	secret, err := config.FixtureCredential(a.snapshot.RunID, a.snapshot.Origin, actionID, a.snapshot.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		if recordErr := a.deny(ctx, a.rule.URL); recordErr != nil {
			return recordErr
		}
		return err
	}
	observation, encoded, err := a.fetcher.postAuth(ctx, a.rule.URL, secret)
	secret = ""
	if err != nil {
		return err
	}
	if observation.Status != http.StatusNoContent || observation.Truncated || observation.Bytes != 0 {
		return errors.New("fixture authentication response did not match the adapter contract")
	}
	var raw store.RawHTTP
	if err := json.Unmarshal(encoded, &raw); err != nil {
		return errors.New("fixture authentication response invalid")
	}
	cookie, expiry, err := checkedFixtureCookie(raw, a.rule.URL)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	a.cookie, a.expires = cookie, expiry
	return nil
}

func checkedFixtureCookie(raw store.RawHTTP, authURL string) (string, time.Time, error) {
	u, err := url.Parse(authURL)
	if err != nil || raw.RequestURL != authURL || raw.Method != http.MethodPost || raw.Status != http.StatusNoContent || len(raw.Body) != 0 || raw.Truncated {
		return "", time.Time{}, errors.New("fixture authentication response invalid")
	}
	set := raw.Header.Values("Set-Cookie")
	if len(set) != 1 {
		return "", time.Time{}, errors.New("fixture authentication cookie contract invalid")
	}
	parts := strings.Split(set[0], ";")
	attributes := make(map[string]bool)
	for _, part := range parts[1:] {
		name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
		name = strings.ToLower(strings.TrimSpace(name))
		switch name {
		case "path", "httponly", "samesite", "max-age", "expires", "secure":
		default:
			return "", time.Time{}, errors.New("fixture authentication cookie attribute invalid")
		}
		if attributes[name] {
			return "", time.Time{}, errors.New("fixture authentication cookie attribute repeated")
		}
		attributes[name] = true
	}
	if !attributes["path"] || !attributes["httponly"] || !attributes["samesite"] || !attributes["max-age"] || attributes["secure"] != (u.Scheme == "https") {
		return "", time.Time{}, errors.New("fixture authentication cookie attributes incomplete")
	}
	cookies := (&http.Response{Header: raw.Header}).Cookies()
	if len(cookies) != 1 {
		return "", time.Time{}, errors.New("fixture authentication cookie contract invalid")
	}
	c := cookies[0]
	if c.Name != "shadow_fixture_session" || c.Value == "" || len(c.Value) > 512 || strings.ContainsAny(c.Value, " \t\r\n;,") || c.Domain != "" || c.Path != "/" || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Secure != (u.Scheme == "https") || c.MaxAge <= 0 || c.MaxAge > 600 {
		return "", time.Time{}, errors.New("fixture authentication cookie scope invalid")
	}
	now := time.Now()
	expiry := now.Add(time.Duration(c.MaxAge) * time.Second)
	if !c.Expires.IsZero() {
		if !c.Expires.After(now) || c.Expires.After(expiry) {
			return "", time.Time{}, errors.New("fixture authentication cookie expiry invalid")
		}
		expiry = c.Expires
	}
	return c.Name + "=" + c.Value, expiry, nil
}

func (a *fixtureAuthenticator) read(ctx context.Context, actionID string) (Observation, int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.current(ctx); err != nil {
		return Observation{}, 0, err
	}
	rawURL, ok := a.reader.reads[actionID]
	if !ok {
		return Observation{}, 0, errors.New("fixture read action is not granted")
	}
	if a.cookie == "" || !time.Now().Before(a.expires) {
		a.cookie = ""
		return Observation{}, 0, errors.New("fixture session absent, expired, or read action ungranted")
	}
	if !a.store.EvidenceKeyReady() {
		return Observation{}, 0, errors.New("fixture evidence key unavailable")
	}
	ctx, cancel := context.WithDeadline(ctx, a.expires)
	defer cancel()
	observation, evidence, err := a.reader.fetcher.getWithCookie(ctx, rawURL, a.cookie)
	if err != nil {
		return Observation{}, 0, err
	}
	id, err := a.store.RecordObservationForSnapshot(ctx, a.snapshot, store.EvidenceSummary(observation), evidence)
	if err != nil {
		return Observation{}, 0, err
	}
	return observation, id, nil
}

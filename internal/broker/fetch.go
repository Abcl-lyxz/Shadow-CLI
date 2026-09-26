package broker

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"shadow/internal/policy"
	"shadow/internal/store"
)

const (
	maxBody      = 256 << 10
	maxRedirects = 5
	maxRequests  = 20
)

var blockedDestinations = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), // shared address space, including common metadata endpoints
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
}

// An explicit URL list is required because a GET method alone does not
// establish that an endpoint is free of side effects. Not an agent tool.
type Options struct {
	AllowedURLs   []string
	AllowLoopback bool // local fixtures only
	lookup        func(context.Context, string) ([]net.IP, error)
	interval      time.Duration
}

type Fetcher struct {
	scope        policy.Scope
	ip           net.IP
	allowed      map[string]struct{}
	gate         chan struct{}
	mu           sync.Mutex
	used         int
	last         time.Time
	interval     time.Duration
	requestLimit int
	guard        func(context.Context, string) error
	cleanupOnly  bool
}

// Observation excludes body bytes, headers, path, and query. Hashes identify
// the requested URL and the capped response prefix without exposing content.
type Observation struct {
	Origin      string `json:"origin"`
	URLSHA256   string `json:"url_sha256"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Bytes       int    `json:"bytes"`
	SHA256      string `json:"sha256"`
	Truncated   bool   `json:"truncated"`
}

func New(ctx context.Context, scope policy.Scope, opts Options) (*Fetcher, error) {
	u, err := url.Parse(scope.Origin)
	if err != nil || u.Hostname() == "" || !scope.Allows(scope.Origin) {
		return nil, errors.New("invalid scope")
	}
	if len(opts.AllowedURLs) == 0 {
		return nil, errors.New("explicit allowed URLs are required")
	}
	allowed := make(map[string]struct{}, len(opts.AllowedURLs))
	for _, raw := range opts.AllowedURLs {
		candidate, err := checkedURL(scope, raw)
		if err != nil {
			return nil, errors.New("allowed URL is outside exact-origin scope or malformed")
		}
		allowed[candidate.String()] = struct{}{}
	}
	lookup := opts.lookup
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", host)
		}
	}
	ips, err := lookup(ctx, u.Hostname())
	if err != nil || len(ips) == 0 {
		return nil, errors.New("target DNS resolution failed")
	}
	for _, ip := range ips {
		if !allowedDestination(ip, opts.AllowLoopback) {
			return nil, errors.New("target DNS includes a disallowed destination")
		}
	}
	interval := time.Second
	if opts.interval > 0 {
		interval = opts.interval
	}
	return &Fetcher{scope: scope, ip: ips[0], allowed: allowed, gate: make(chan struct{}, 1), interval: interval, requestLimit: maxRequests}, nil
}

func allowedDestination(ip net.IP, allowLoopback bool) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() {
		return allowLoopback
	}
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, prefix := range blockedDestinations {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func checkedURL(scope policy.Scope, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Opaque != "" || u.Fragment != "" || u.RawFragment != "" || !scope.Allows(raw) {
		return nil, errors.New("URL is outside exact-origin scope or malformed")
	}
	return u, nil
}

func (f *Fetcher) reserve(ctx context.Context) error {
	f.mu.Lock()
	if f.used >= f.requestLimit {
		f.mu.Unlock()
		return errors.New("request budget exhausted")
	}
	wait := time.Until(f.last.Add(f.interval))
	f.mu.Unlock()
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	f.used++
	f.last = time.Now()
	f.mu.Unlock()
	return nil
}

func (f *Fetcher) Get(ctx context.Context, raw string) (Observation, error) {
	observation, _, err := f.get(ctx, raw)
	return observation, err
}

// GetRecorded is the fixture-only path for evidence-backed observations.
// It returns no observation when the encrypted evidence transaction fails.
func (f *Fetcher) GetRecorded(ctx context.Context, runID, raw string, st *store.Store) (Observation, int64, error) {
	if st == nil || runID == "" {
		return Observation{}, 0, errors.New("evidence store and run id required")
	}
	observation, evidence, err := f.get(ctx, raw)
	if err != nil {
		return Observation{}, 0, err
	}
	id, err := st.RecordObservation(ctx, runID, store.EvidenceSummary(observation), evidence)
	if err != nil {
		return Observation{}, 0, err
	}
	return observation, id, nil
}

func (f *Fetcher) get(ctx context.Context, raw string) (Observation, []byte, error) {
	if f.cleanupOnly {
		return Observation{}, nil, errors.New("cleanup fetcher cannot read")
	}
	return f.request(ctx, http.MethodGet, raw)
}

// delete is used only by the run-bound loopback cleanup executor. A DELETE
// redirect is never followed because its effect at the next URL is unknown.
func (f *Fetcher) delete(ctx context.Context, raw string) (Observation, error) {
	if !f.cleanupOnly {
		return Observation{}, errors.New("read fetcher cannot delete")
	}
	observation, _, err := f.request(ctx, http.MethodDelete, raw)
	return observation, err
}

func (f *Fetcher) request(ctx context.Context, method, raw string) (Observation, []byte, error) {
	if method != http.MethodGet && method != http.MethodDelete {
		return Observation{}, nil, errors.New("unsupported fixture request method")
	}
	current, err := checkedURL(f.scope, raw)
	if err != nil {
		return Observation{}, nil, err
	}
	select {
	case f.gate <- struct{}{}:
		defer func() { <-f.gate }()
	case <-ctx.Done():
		return Observation{}, nil, ctx.Err()
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		Proxy:                  nil,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil || !strings.EqualFold(host, current.Hostname()) || port != targetPort(current) {
				return nil, errors.New("network destination changed")
			}
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort(f.ip.String(), port))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 20 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for redirects := 0; ; redirects++ {
		if f.guard != nil {
			if err := f.guard(ctx, current.String()); err != nil {
				return Observation{}, nil, err
			}
		}
		if _, ok := f.allowed[current.String()]; !ok {
			return Observation{}, nil, errors.New("URL is not explicitly allowed")
		}
		if err := f.reserve(ctx); err != nil {
			return Observation{}, nil, err
		}
		req, err := http.NewRequestWithContext(ctx, method, current.String(), nil)
		if err != nil {
			return Observation{}, nil, errors.New("invalid request URL")
		}
		req.Header.Set("User-Agent", "Shadow-CLI/0.1 authorized-security-test")
		resp, err := client.Do(req)
		if err != nil {
			return Observation{}, nil, errors.New("target request failed")
		}
		if isRedirect(resp.StatusCode) {
			location := resp.Header.Get("Location")
			resp.Body.Close()
			if method != http.MethodGet {
				return Observation{}, nil, errors.New("fixture cleanup redirect denied")
			}
			if redirects >= maxRedirects || location == "" {
				return Observation{}, nil, errors.New("redirect limit reached or location missing")
			}
			next, err := url.Parse(location)
			if err != nil {
				return Observation{}, nil, errors.New("invalid redirect location")
			}
			current, err = checkedURL(f.scope, current.ResolveReference(next).String())
			if err != nil {
				return Observation{}, nil, errors.New("redirect left exact-origin scope")
			}
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
		resp.Body.Close()
		if err != nil {
			return Observation{}, nil, errors.New("response body read failed")
		}
		truncated := len(body) > maxBody
		if truncated {
			body = body[:maxBody]
		}
		bodyHash := sha256.Sum256(body)
		urlHash := sha256.Sum256([]byte(current.String()))
		contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if err != nil || len(contentType) > 128 {
			contentType = ""
		}
		observation := Observation{Origin: f.scope.Origin, URLSHA256: hex.EncodeToString(urlHash[:]), Status: resp.StatusCode, ContentType: contentType, Bytes: len(body), SHA256: hex.EncodeToString(bodyHash[:]), Truncated: truncated}
		evidence, err := json.Marshal(store.RawHTTP{RequestURL: current.String(), Method: method, Status: resp.StatusCode, Header: resp.Header.Clone(), Body: body, Truncated: truncated})
		if err != nil {
			return Observation{}, nil, errors.New("raw response encoding failed")
		}
		return observation, evidence, nil
	}
}

func isRedirect(status int) bool {
	return status == http.StatusMovedPermanently || status == http.StatusFound || status == http.StatusSeeOther || status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect
}

func targetPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Port()
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func (f *Fetcher) IP() string { return f.ip.String() }

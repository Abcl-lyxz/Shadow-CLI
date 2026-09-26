package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
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
	allowedURLs   []string
	AllowLoopback bool // local fixtures only
	lookup        func(context.Context, string) ([]net.IP, error)
	interval      time.Duration
}

type fetcher struct {
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
	deny         func(context.Context, string) error
	reserveRun   func(context.Context) (func() error, error)
	cleanupOnly  bool
	writeOnly    bool
	authOnly     bool
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

func newFetcher(ctx context.Context, scope policy.Scope, opts Options) (*fetcher, error) {
	u, err := url.Parse(scope.Origin)
	if err != nil || u.Hostname() == "" || !scope.Allows(scope.Origin) {
		return nil, errors.New("invalid scope")
	}
	if len(opts.allowedURLs) == 0 {
		return nil, errors.New("explicit allowed URLs are required")
	}
	allowed := make(map[string]struct{}, len(opts.allowedURLs))
	for _, raw := range opts.allowedURLs {
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
	return &fetcher{scope: scope, ip: ips[0], allowed: allowed, gate: make(chan struct{}, 1), interval: interval, requestLimit: maxRequests}, nil
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

func (f *fetcher) reserve(ctx context.Context) (func() error, error) {
	if f.reserveRun != nil {
		return f.reserveRun(ctx)
	}
	f.mu.Lock()
	if f.used >= f.requestLimit {
		f.mu.Unlock()
		return nil, errors.New("request budget exhausted")
	}
	wait := time.Until(f.last.Add(f.interval))
	f.mu.Unlock()
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.mu.Lock()
	f.used++
	f.last = time.Now()
	f.mu.Unlock()
	return func() error { return nil }, nil
}

func (f *fetcher) getObservation(ctx context.Context, raw string) (Observation, error) {
	observation, _, err := f.get(ctx, raw)
	return observation, err
}

func (f *fetcher) get(ctx context.Context, raw string) (Observation, []byte, error) {
	if f.cleanupOnly || f.writeOnly || f.authOnly {
		return Observation{}, nil, errors.New("mutation fetcher cannot read")
	}
	return f.request(ctx, http.MethodGet, raw, nil)
}

func (f *fetcher) getWithCookie(ctx context.Context, raw, cookie string) (Observation, []byte, error) {
	if f.cleanupOnly || f.writeOnly || f.authOnly || cookie == "" {
		return Observation{}, nil, errors.New("authenticated fixture read unavailable")
	}
	return f.requestWithHeaders(ctx, http.MethodGet, raw, nil, http.Header{"Cookie": []string{cookie}}, true)
}

func (f *fetcher) postAuth(ctx context.Context, raw, secret string) (Observation, []byte, error) {
	if !f.authOnly || f.writeOnly || f.cleanupOnly || secret == "" {
		return Observation{}, nil, errors.New("fixture authentication unavailable")
	}
	body, err := json.Marshal(struct {
		Credential string `json:"credential"`
	}{Credential: secret})
	if err != nil {
		return Observation{}, nil, errors.New("fixture credential encoding failed")
	}
	return f.requestWithHeaders(ctx, http.MethodPost, raw, body, nil, true)
}

// delete is used only by the run-bound loopback cleanup executor. A DELETE
// redirect is never followed because its effect at the next URL is unknown.
func (f *fetcher) delete(ctx context.Context, raw string) (Observation, error) {
	if !f.cleanupOnly {
		return Observation{}, errors.New("read fetcher cannot delete")
	}
	observation, _, err := f.request(ctx, http.MethodDelete, raw, nil)
	return observation, err
}

// postMarker sends only the fixture's fixed marker contract. The caller cannot
// supply arbitrary bytes, headers, or a method to this mutation fetcher.
func (f *fetcher) postMarker(ctx context.Context, raw, resource string) (Observation, error) {
	if !f.writeOnly || f.cleanupOnly || f.authOnly {
		return Observation{}, errors.New("fixture writer unavailable")
	}
	body, err := json.Marshal(struct {
		Resource string `json:"resource"`
	}{Resource: resource})
	if err != nil {
		return Observation{}, err
	}
	observation, _, err := f.request(ctx, http.MethodPost, raw, body)
	return observation, err
}

func (f *fetcher) request(ctx context.Context, method, raw string, body []byte) (Observation, []byte, error) {
	return f.requestWithHeaders(ctx, method, raw, body, nil, false)
}

func (f *fetcher) requestWithHeaders(ctx context.Context, method, raw string, body []byte, headers http.Header, noRedirect bool) (Observation, []byte, error) {
	if method != http.MethodGet && method != http.MethodDelete && method != http.MethodPost {
		return Observation{}, nil, errors.New("unsupported fixture request method")
	}
	if method == http.MethodPost && (!(f.writeOnly || f.authOnly) || len(body) == 0) || method != http.MethodPost && len(body) != 0 {
		return Observation{}, nil, errors.New("invalid fixture request body")
	}
	current, err := checkedURL(f.scope, raw)
	if err != nil {
		if f.deny != nil {
			if recordErr := f.deny(ctx, raw); recordErr != nil {
				return Observation{}, nil, recordErr
			}
		}
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
		status, responseHeader, responseBody, err := func() (status int, header http.Header, data []byte, err error) {
			release, err := f.reserve(ctx)
			if err != nil {
				return 0, nil, nil, err
			}
			defer func() {
				if releaseErr := release(); releaseErr != nil && err == nil {
					err = releaseErr
				}
			}()
			req, err := http.NewRequestWithContext(ctx, method, current.String(), bytes.NewReader(body))
			if err != nil {
				return 0, nil, nil, errors.New("invalid request URL")
			}
			req.Header.Set("User-Agent", "Shadow-CLI/0.1 authorized-security-test")
			for name, values := range headers {
				for _, value := range values {
					req.Header.Add(name, value)
				}
			}
			if method == http.MethodPost {
				req.Header.Set("Content-Type", "application/json")
			}
			resp, err := client.Do(req)
			if err != nil {
				return 0, nil, nil, errors.New("target request failed")
			}
			defer resp.Body.Close()
			if isRedirect(resp.StatusCode) {
				return resp.StatusCode, resp.Header.Clone(), nil, nil
			}
			responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
			if err != nil {
				return 0, nil, nil, errors.New("response body read failed")
			}
			return resp.StatusCode, resp.Header.Clone(), responseBody, nil
		}()
		if err != nil {
			return Observation{}, nil, err
		}
		if isRedirect(status) {
			location := responseHeader.Get("Location")
			if method != http.MethodGet || noRedirect {
				return Observation{}, nil, errors.New("fixture mutation redirect denied")
			}
			if redirects >= maxRedirects || location == "" {
				return Observation{}, nil, errors.New("redirect limit reached or location missing")
			}
			next, err := url.Parse(location)
			if err != nil {
				return Observation{}, nil, errors.New("invalid redirect location")
			}
			resolved := current.ResolveReference(next).String()
			current, err = checkedURL(f.scope, resolved)
			if err != nil {
				if f.deny != nil {
					if recordErr := f.deny(ctx, resolved); recordErr != nil {
						return Observation{}, nil, recordErr
					}
				}
				return Observation{}, nil, errors.New("redirect left exact-origin scope")
			}
			continue
		}
		truncated := len(responseBody) > maxBody
		if truncated {
			responseBody = responseBody[:maxBody]
		}
		bodyHash := sha256.Sum256(responseBody)
		urlHash := sha256.Sum256([]byte(current.String()))
		contentType := store.SafeContentType(responseHeader.Get("Content-Type"))
		observation := Observation{Origin: f.scope.Origin, URLSHA256: hex.EncodeToString(urlHash[:]), Status: status, ContentType: contentType, Bytes: len(responseBody), SHA256: hex.EncodeToString(bodyHash[:]), Truncated: truncated}
		evidence, err := json.Marshal(store.RawHTTP{RequestURL: current.String(), Method: method, Status: status, Header: responseHeader, Body: responseBody, Truncated: truncated})
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

func (f *fetcher) ipString() string { return f.ip.String() }

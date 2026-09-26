package policy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

type Scope struct {
	Origin string `json:"origin"`
}

func FromTarget(raw string) (Scope, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return Scope{}, errors.New("target must be an http or https URL without userinfo")
	}
	if strings.Contains(u.Hostname(), "%") {
		return Scope{}, errors.New("zone identifiers are not allowed")
	}
	if p := u.Port(); p != "" {
		if _, err := net.LookupPort("tcp", p); err != nil {
			return Scope{}, fmt.Errorf("invalid target port: %w", err)
		}
	}
	return Scope{Origin: u.Scheme + "://" + strings.ToLower(u.Host)}, nil
}

func (s Scope) Allows(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.User != nil {
		return false
	}
	return strings.EqualFold(u.Scheme+"://"+u.Host, s.Origin)
}

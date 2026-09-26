package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const URL = "https://models.dev/api.json"

type Model struct {
	Name     string `json:"name"`
	ToolCall bool   `json:"tool_call"`
	Limit    struct {
		Context int `json:"context"`
		Output  int `json:"output"`
	} `json:"limit"`
}

type Provider struct {
	ID     string           `json:"-"`
	Name   string           `json:"name"`
	API    string           `json:"api"`
	NPM    string           `json:"npm"`
	Models map[string]Model `json:"models"`
}

type Catalog map[string]Provider

func Fetch(ctx context.Context, client *http.Client) (Catalog, error) {
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("catalog returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if len(body) == 32<<20 {
		return nil, errors.New("catalog exceeds size limit")
	}
	return decode(body)
}

func decode(body []byte) (Catalog, error) {
	var data Catalog
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("empty provider catalog")
	}
	for id, p := range data {
		p.ID = id
		data[id] = p
	}
	return data, nil
}

// Load prefers the live catalog and falls back to the last valid local copy.
func Load(ctx context.Context, client *http.Client, cachePath string) (Catalog, bool, error) {
	data, fetchErr := Fetch(ctx, client)
	if fetchErr == nil {
		if cachePath != "" {
			if body, err := json.Marshal(data); err == nil {
				if err := os.MkdirAll(filepath.Dir(cachePath), 0700); err == nil {
					tmp := cachePath + ".tmp"
					if err := os.WriteFile(tmp, body, 0600); err == nil {
						_ = os.Rename(tmp, cachePath)
					}
				}
			}
		}
		return data, false, nil
	}
	if cachePath == "" {
		return nil, false, fetchErr
	}
	file, err := os.Open(cachePath)
	if err != nil {
		return nil, false, fetchErr
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, (32<<20)+1))
	if err != nil || len(body) > 32<<20 {
		return nil, false, fetchErr
	}
	data, err = decode(body)
	if err != nil {
		return nil, false, fetchErr
	}
	return data, true, nil
}

func (c Catalog) Search(query string, limit int) []Provider {
	query = strings.ToLower(strings.TrimSpace(query))
	var out []Provider
	for _, p := range c {
		if query == "" || strings.Contains(strings.ToLower(p.ID), query) || strings.Contains(strings.ToLower(p.Name), query) {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (p Provider) ToolModels() []string {
	var ids []string
	for id, m := range p.Models {
		if m.ToolCall {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

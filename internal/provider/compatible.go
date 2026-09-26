package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

type ToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type Tool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

type Client struct {
	BaseURL string
	Key     string
	HTTP    *http.Client
}

type Usage struct {
	InputTokens  int64
	OutputTokens int64
	Known        bool
}

func (c Client) endpoint(path string) (string, error) {
	u, err := url.Parse(strings.TrimRight(c.BaseURL, "/"))
	if err != nil || u == nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		// Plain HTTP is permitted only for local model servers.
		if err != nil || u == nil || u.Scheme != "http" || u.Hostname() == "" || u.User != nil {
			return "", errors.New("provider base URL must be HTTPS or local HTTP")
		}
		host := strings.ToLower(u.Hostname())
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return "", errors.New("non-local provider HTTP is forbidden")
		}
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("provider base URL cannot contain query or fragment")
	}
	return strings.TrimRight(u.String(), "/") + path, nil
}

func (c Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{
		Timeout: 90 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("provider redirect blocked")
		},
	}
}

func (c Client) Models(ctx context.Context) ([]string, error) {
	endpoint, err := c.endpoint("/models")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Key)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("models request failed: %s", resp.Status)
	}
	var data struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&data); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(data.Data))
	for _, m := range data.Data {
		if m.ID != "" {
			ids = append(ids, m.ID)
		}
	}
	return ids, nil
}

func (c Client) Chat(ctx context.Context, model string, messages []Message, tools []Tool) (Message, error) {
	message, _, err := c.ChatWithUsage(ctx, model, messages, tools)
	return message, err
}

func (c Client) ChatWithUsage(ctx context.Context, model string, messages []Message, tools []Tool) (Message, Usage, error) {
	return c.ChatWithUsageLimit(ctx, model, messages, tools, 0)
}

func (c Client) ChatWithUsageLimit(ctx context.Context, model string, messages []Message, tools []Tool, maxOutputTokens int64) (Message, Usage, error) {
	endpoint, err := c.endpoint("/chat/completions")
	if err != nil {
		return Message{}, Usage{}, err
	}
	request := map[string]any{"model": model, "messages": messages}
	if maxOutputTokens > 0 {
		request["max_tokens"] = maxOutputTokens
	}
	if len(tools) > 0 {
		request["tools"] = tools
	}
	body, err := json.Marshal(request)
	if err != nil {
		return Message{}, Usage{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Message{}, Usage{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return Message{}, Usage{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Message{}, Usage{}, fmt.Errorf("model request failed: %s", resp.Status)
	}
	var data struct {
		Usage *struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
		} `json:"usage"`
		Choices []struct {
			Message Message `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&data); err != nil {
		return Message{}, Usage{}, err
	}
	if len(data.Choices) == 0 {
		return Message{}, Usage{}, errors.New("provider returned no choices")
	}
	usage := Usage{}
	if data.Usage != nil && data.Usage.PromptTokens >= 0 && data.Usage.CompletionTokens >= 0 {
		usage = Usage{InputTokens: data.Usage.PromptTokens, OutputTokens: data.Usage.CompletionTokens, Known: true}
	}
	return data.Choices[0].Message, usage, nil
}

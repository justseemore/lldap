package lldap

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
	"sync"
	"time"
)

const (
	loginPath   = "/auth/simple/login"
	refreshPath = "/auth/refresh"
	graphqlPath = "/api/graphql"
)

var (
	ErrUnauthenticated    = errors.New("lldap: not authenticated")
	ErrInvalidCredentials = errors.New("lldap: invalid credentials")
	ErrNotFound           = errors.New("lldap: not found")
)

// Error 是 GraphQL 业务错误。
// lldap 通常返回 HTTP 200 + errors 数组。
type Error struct {
	Message    string         `json:"message"`
	Path       []any          `json:"path,omitempty"`
	Extensions map[string]any `json:"extensions,omitempty"`
}

func (e Error) Error() string {
	return e.Message
}

type Errors []Error

func (e Errors) Error() string {
	if len(e) == 0 {
		return "lldap: graphql error"
	}
	if len(e) == 1 {
		return "lldap: graphql: " + e[0].Message
	}
	return fmt.Sprintf("lldap: graphql: %s (+%d more)", e[0].Message, len(e)-1)
}

type httpError struct {
	code int
	body string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("lldap: http %d: %s", e.code, e.body)
}

type Client struct {
	baseURL string
	http    *http.Client

	mu           sync.RWMutex
	token        string
	refreshToken string

	refreshMu sync.Mutex
}

type Option func(*Client)

func WithHTTPClient(h *http.Client) Option {
	return func(c *Client) {
		if h != nil {
			c.http = h
		}
	}
}

func New(baseURL string, opts ...Option) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("lldap: parse base url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("lldap: base url must be http(s), got %q", u.Scheme)
	}

	c := &Client{
		baseURL: u.String(),
		http:    &http.Client{Timeout: 15 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
}

// Login 调 /auth/simple/login，拿到 JWT 和 refresh token。
// 生产环境务必通过 HTTPS 调用，因为密码是明文 JSON。
func (c *Client) Login(ctx context.Context, username, password string) error {
	payload, err := json.Marshal(loginRequest{
		Username: username,
		Password: password,
	})
	if err != nil {
		return fmt.Errorf("lldap: encode login: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+loginPath,
		bytes.NewReader(payload),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("lldap: login: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("lldap: read login response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return &httpError{
			code: resp.StatusCode,
			body: strings.TrimSpace(string(body)),
		}
	}

	var ar authResponse
	if err := json.Unmarshal(body, &ar); err != nil {
		return fmt.Errorf("lldap: decode login response: %w", err)
	}
	if ar.Token == "" {
		return errors.New("lldap: login response has no token")
	}

	c.mu.Lock()
	c.token = ar.Token
	c.refreshToken = ar.RefreshToken
	c.mu.Unlock()
	return nil
}

// Refresh 调 GET /auth/refresh。
// refresh token 放在 refresh_token cookie 里。
func (c *Client) Refresh(ctx context.Context) error {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()

	c.mu.RLock()
	rt := c.refreshToken
	c.mu.RUnlock()
	if rt == "" {
		return ErrUnauthenticated
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		c.baseURL+refreshPath,
		nil,
	)
	if err != nil {
		return err
	}
	req.AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: rt,
	})

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("lldap: refresh: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("lldap: read refresh response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: refresh http %d", ErrUnauthenticated, resp.StatusCode)
	}

	var ar authResponse
	if err := json.Unmarshal(body, &ar); err != nil {
		return fmt.Errorf("lldap: decode refresh response: %w", err)
	}
	if ar.Token == "" {
		return fmt.Errorf("%w: empty refresh token", ErrUnauthenticated)
	}

	c.mu.Lock()
	c.token = ar.Token
	if ar.RefreshToken != "" {
		c.refreshToken = ar.RefreshToken
	}
	c.mu.Unlock()
	return nil
}

func (c *Client) currentToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token
}

type graphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables,omitempty"`
}

type graphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors Errors          `json:"errors"`
}

func (c *Client) do(
	ctx context.Context,
	query string,
	vars map[string]any,
	out any,
) error {
	payload, err := json.Marshal(graphQLRequest{
		Query:     query,
		Variables: vars,
	})
	if err != nil {
		return fmt.Errorf("lldap: encode graphql: %w", err)
	}

	err = c.doOnce(ctx, payload, out)
	var he *httpError
	if errors.As(err, &he) && he.code == http.StatusUnauthorized {
		if rerr := c.Refresh(ctx); rerr != nil {
			return fmt.Errorf("%w: refresh: %v", ErrUnauthenticated, rerr)
		}
		return c.doOnce(ctx, payload, out)
	}
	return err
}

func (c *Client) doOnce(ctx context.Context, payload []byte, out any) error {
	tok := c.currentToken()
	if tok == "" {
		return ErrUnauthenticated
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+graphqlPath,
		bytes.NewReader(payload),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("lldap: graphql: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("lldap: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return &httpError{
			code: resp.StatusCode,
			body: strings.TrimSpace(string(raw)),
		}
	}

	var gr graphQLResponse
	if err := json.Unmarshal(raw, &gr); err != nil {
		return fmt.Errorf("lldap: decode response: %w", err)
	}
	if len(gr.Errors) > 0 {
		return gr.Errors
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(gr.Data, out); err != nil {
		return fmt.Errorf("lldap: decode data: %w", err)
	}
	return nil
}

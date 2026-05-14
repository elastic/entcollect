// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package entraid

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const tokenGrace = 30 * time.Second

// tokenSource manages OAuth2 client credentials tokens for the
// Microsoft identity platform. It caches the access token and
// refreshes it before expiry (by tokenGrace) to avoid races
// between the validity check and the request reaching the API.
type tokenSource struct {
	clientID     string
	clientSecret string
	tokenURL     string
	scopes       []string
	client       *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

// newTokenSource creates a tokenSource from the provider config. It
// constructs the token URL from the login endpoint and tenant ID.
func newTokenSource(cfg Config, client *http.Client) *tokenSource {
	tokenURL := strings.TrimRight(cfg.LoginEndpoint, "/") + "/" + cfg.TenantID + "/oauth2/v2.0/token"
	scopes := cfg.LoginScopes
	if len(scopes) == 0 {
		scopes = defaultLoginScopes
	}
	return &tokenSource{
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		tokenURL:     tokenURL,
		scopes:       scopes,
		client:       client,
	}
}

// Reset clears the cached token, forcing the next call to Token to
// re-authenticate. Used when the API returns 401 Unauthorized.
func (ts *tokenSource) Reset() {
	ts.mu.Lock()
	ts.token = ""
	ts.mu.Unlock()
}

// Token returns a valid access token, refreshing it if expired.
func (ts *tokenSource) Token(ctx context.Context) (string, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.token != "" && time.Now().Before(ts.expires.Add(-tokenGrace)) {
		return ts.token, nil
	}

	data := url.Values{
		"client_id":     {ts.clientID},
		"scope":         {strings.Join(ts.scopes, " ")},
		"client_secret": {ts.clientSecret},
		"grant_type":    {"client_credentials"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ts.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp authErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil && errResp.Error != "" {
			return "", fmt.Errorf("token exchange failed: %s: %s", errResp.Error, errResp.Description)
		}
		return "", fmt.Errorf("token exchange failed: HTTP %d", resp.StatusCode)
	}

	var tok authTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}

	ts.token = tok.AccessToken
	ts.expires = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	return ts.token, nil
}

type authTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type authErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

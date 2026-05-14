// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// This file uses go-jose/v4 for JWK parsing and JWT signing rather than
// golang-jwt/jwt/v5 (which the legacy Okta provider uses). go-jose
// provides native JWK-to-key conversion, avoiding the manual RSA
// big-integer unmarshalling the legacy code needs. Since we're handling
// cryptographic key material, using a purpose-built library maintained
// by the Let's Encrypt/Certbot team is worth the dependency.

package okta

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// OAuth2Config holds OAuth2 configuration for the Okta provider.
// JWK is raw JSON bytes representing an RSA private key in JWK format.
// The adapter reads from file or PEM and converts before constructing
// this struct.
type OAuth2Config struct {
	ClientID     string          `json:"client_id"`
	ClientSecret string          `json:"client_secret,omitempty"`
	TokenURL     string          `json:"token_url"`
	Scopes       []string        `json:"scopes,omitempty"`
	JWK          json.RawMessage `json:"jwk,omitempty"`
}

func (o *OAuth2Config) validate() error {
	switch {
	case o.ClientID == "":
		return errOAuth2MissingClientID
	case o.TokenURL == "":
		return errOAuth2MissingTokenURL
	case len(o.Scopes) == 0:
		return errOAuth2MissingScopes
	case o.ClientSecret == "" && len(o.JWK) == 0:
		return errOAuth2NoCreds
	case o.ClientSecret != "" && len(o.JWK) > 0:
		return errOAuth2BothCreds
	}
	return nil
}

// newOAuth2Client creates an HTTP client with an OAuth2 transport.
func newOAuth2Client(ctx context.Context, base *http.Client, cfg OAuth2Config) (*http.Client, error) {
	oauthConfig := &oauth2.Config{
		ClientID: cfg.ClientID,
		Scopes:   cfg.Scopes,
		Endpoint: oauth2.Endpoint{
			TokenURL: cfg.TokenURL,
		},
	}

	hasSecret := cfg.ClientSecret != ""
	hasJWK := len(cfg.JWK) > 0

	var tokenSource oauth2.TokenSource
	switch {
	case hasSecret:
		tokenSource = &clientSecretTokenSource{
			ctx:          ctx,
			conf:         oauthConfig,
			clientSecret: cfg.ClientSecret,
			client:       base,
		}
	case hasJWK:
		signed, err := generateJWT(cfg.JWK, oauthConfig)
		if err != nil {
			return nil, fmt.Errorf("generate JWT: %w", err)
		}
		token, err := exchangeForBearerToken(ctx, signed, oauthConfig, base)
		if err != nil {
			return nil, fmt.Errorf("exchange JWT for bearer token: %w", err)
		}
		tokenSource = &jwtTokenSource{
			ctx:    ctx,
			conf:   oauthConfig,
			jwk:    cfg.JWK,
			client: base,
			token:  token,
		}
	default:
		return nil, errors.New("no OAuth2 credentials provided (need client_secret or jwk)")
	}

	ctxWithClient := context.WithValue(ctx, oauth2.HTTPClient, base)
	return oauth2.NewClient(ctxWithClient, tokenSource), nil
}

// jwtTokenSource implements oauth2.TokenSource for JWT client assertion.
type jwtTokenSource struct {
	ctx    context.Context
	conf   *oauth2.Config
	jwk    json.RawMessage
	client *http.Client

	mu    sync.Mutex
	token *oauth2.Token
}

func (ts *jwtTokenSource) Token() (*oauth2.Token, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.token != nil && ts.token.Valid() {
		return ts.token, nil
	}

	signed, err := generateJWT(ts.jwk, ts.conf)
	if err != nil {
		return nil, fmt.Errorf("generate JWT: %w", err)
	}
	token, err := exchangeForBearerToken(ts.ctx, signed, ts.conf, ts.client)
	if err != nil {
		return nil, fmt.Errorf("exchange JWT for bearer token: %w", err)
	}
	ts.token = token
	return token, nil
}

// clientSecretTokenSource implements oauth2.TokenSource for client_credentials
// with a client secret.
type clientSecretTokenSource struct {
	ctx          context.Context
	conf         *oauth2.Config
	clientSecret string
	client       *http.Client

	mu    sync.Mutex
	token *oauth2.Token
}

func (cs *clientSecretTokenSource) Token() (*oauth2.Token, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if cs.token != nil && cs.token.Valid() {
		return cs.token, nil
	}

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", strings.Join(cs.conf.Scopes, " "))
	data.Set("client_id", cs.conf.ClientID)
	data.Set("client_secret", cs.clientSecret)

	req, err := http.NewRequestWithContext(cs.ctx, "POST", cs.conf.Endpoint.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := cs.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("exchange client credentials: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: HTTP %d", resp.StatusCode)
	}

	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}

	cs.token = &oauth2.Token{
		AccessToken: tok.AccessToken,
		TokenType:   tok.TokenType,
		Expiry:      time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second),
	}
	return cs.token, nil
}

// generateJWT creates a signed JWT client assertion from a JWK in JSON
// format. Uses go-jose/v4 for JWK parsing and signing.
func generateJWT(jwkJSON json.RawMessage, cnf *oauth2.Config) (string, error) {
	var jwk jose.JSONWebKey
	if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
		return "", fmt.Errorf("parse JWK: %w", err)
	}

	key, ok := jwk.Key.(crypto.Signer)
	if !ok {
		return "", errors.New("JWK does not contain a signing key")
	}

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("create signer: %w", err)
	}

	now := time.Now()
	claims := josejwt.Claims{
		Issuer:   cnf.ClientID,
		Subject:  cnf.ClientID,
		Audience: josejwt.Audience{cnf.Endpoint.TokenURL},
		IssuedAt: josejwt.NewNumericDate(now),
		Expiry:   josejwt.NewNumericDate(now.Add(time.Hour)),
	}

	signed, err := josejwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	return signed, nil
}

// exchangeForBearerToken exchanges a JWT client assertion for an access token.
func exchangeForBearerToken(ctx context.Context, assertion string, cnf *oauth2.Config, client *http.Client) (*oauth2.Token, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", strings.Join(cnf.Scopes, " "))
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_assertion", assertion)

	ccConfig := &clientcredentials.Config{
		TokenURL:       cnf.Endpoint.TokenURL,
		EndpointParams: data,
	}
	ctxWithClient := context.WithValue(ctx, oauth2.HTTPClient, client)
	return ccConfig.TokenSource(ctxWithClient).Token()
}

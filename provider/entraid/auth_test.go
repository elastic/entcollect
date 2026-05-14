// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package entraid

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestTokenSource_Caching(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q; want application/x-www-form-urlencoded", got)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %s; want POST", r.Method)
		}
		json.NewEncoder(w).Encode(authTokenResponse{
			AccessToken: "tok-abc",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	}))
	defer srv.Close()

	cfg := Config{
		TenantID:      "tenant-1",
		ClientID:      "client-1",
		ClientSecret:  "secret-1",
		LoginEndpoint: srv.URL,
		LoginScopes:   []string{"https://graph.microsoft.com/.default"},
	}
	ts := newTokenSource(cfg, srv.Client())

	ctx := context.Background()

	tok1, err := ts.Token(ctx)
	if err != nil {
		t.Fatalf("first token call: %v", err)
	}
	if tok1 != "tok-abc" {
		t.Errorf("first token = %q; want tok-abc", tok1)
	}

	tok2, err := ts.Token(ctx)
	if err != nil {
		t.Fatalf("second token call: %v", err)
	}
	if tok2 != "tok-abc" {
		t.Errorf("cached token = %q; want tok-abc", tok2)
	}

	if n := calls.Load(); n != 1 {
		t.Errorf("HTTP calls = %d; want 1 (cached)", n)
	}
}

func TestTokenSource_RefreshOnExpiry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		tok := "tok-first"
		expiresIn := 0
		if n > 1 {
			tok = "tok-second"
			expiresIn = 3600
		}
		json.NewEncoder(w).Encode(authTokenResponse{
			AccessToken: tok,
			TokenType:   "Bearer",
			ExpiresIn:   expiresIn,
		})
	}))
	defer srv.Close()

	cfg := Config{
		TenantID:      "tenant-1",
		ClientID:      "client-1",
		ClientSecret:  "secret-1",
		LoginEndpoint: srv.URL,
		LoginScopes:   []string{"https://graph.microsoft.com/.default"},
	}
	ts := newTokenSource(cfg, srv.Client())
	ctx := context.Background()

	tok1, err := ts.Token(ctx)
	if err != nil {
		t.Fatalf("first token call: %v", err)
	}
	if tok1 != "tok-first" {
		t.Errorf("first token = %q; want tok-first", tok1)
	}

	tok2, err := ts.Token(ctx)
	if err != nil {
		t.Fatalf("second token call after expiry: %v", err)
	}
	if tok2 != "tok-second" {
		t.Errorf("refreshed token = %q; want tok-second", tok2)
	}

	if n := calls.Load(); n != 2 {
		t.Errorf("HTTP calls = %d; want 2", n)
	}
}

func TestTokenSource_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(authErrorResponse{
			Error:       "invalid_client",
			Description: "bad credentials",
		})
	}))
	defer srv.Close()

	cfg := Config{
		TenantID:      "tenant-1",
		ClientID:      "client-1",
		ClientSecret:  "wrong",
		LoginEndpoint: srv.URL,
		LoginScopes:   []string{"https://graph.microsoft.com/.default"},
	}
	ts := newTokenSource(cfg, srv.Client())

	_, err := ts.Token(context.Background())
	if err == nil {
		t.Fatal("expected error for bad credentials")
	}
	if !strings.Contains(err.Error(), "invalid_client") {
		t.Errorf("error = %v; want to contain invalid_client", err)
	}
}

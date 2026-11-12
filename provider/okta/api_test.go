// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package okta

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elastic/entcollect"
	"github.com/elastic/entcollect/internal/httpretry"
)

func TestGetUsersRetriesServerError(t *testing.T) {
	setFastRetry(t)
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "unavailable")
			return
		}
		_, _ = io.WriteString(w, `[{"id":"u1","status":"ACTIVE"}]`)
	}))
	defer srv.Close()

	users, _, err := getUsers(t.Context(), srv.Client(), srv.Listener.Addr().String(), "key", nil, OmitNone, fastLimiter(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("getUsers: %v", err)
	}
	if len(users) != 1 || users[0].ID != "u1" {
		t.Errorf("getUsers = %+v; want user u1", users)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("server got %d requests; want 2", got)
	}
}

func TestGetUsersRetryExhaustedKeepsCause(t *testing.T) {
	setFastRetry(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"errorSummary":"internal"}`)
	}))
	defer srv.Close()

	_, _, err := getUsers(t.Context(), srv.Client(), srv.Listener.Addr().String(), "key", nil, OmitNone, fastLimiter(), slog.New(slog.DiscardHandler))
	var e *httpretry.Error
	if !errors.As(err, &e) || e.StatusCode != http.StatusInternalServerError {
		t.Fatalf("getUsers error = %v; want *httpretry.Error with status 500", err)
	}
	if !strings.Contains(err.Error(), "internal") {
		t.Errorf("getUsers error = %q; want it to include the response body", err)
	}
}

func TestGetUsersEmptyClientError(t *testing.T) {
	setFastRetry(t)
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, _, err := getUsers(t.Context(), srv.Client(), srv.Listener.Addr().String(), "key", nil, OmitNone, fastLimiter(), slog.New(slog.DiscardHandler))
	if want := "401 Unauthorized: empty response body"; err == nil || err.Error() != want {
		t.Errorf("getUsers error = %v; want %q", err, want)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("server got %d requests; want 1", got)
	}
}

func TestEmptyNotFoundIsMarked(t *testing.T) {
	setFastRetry(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, _, err := getUserFactors(t.Context(), srv.Client(), srv.Listener.Addr().String(), "key", "u1", fastLimiter(), nil, slog.New(slog.DiscardHandler))
	if !errors.As(err, new(notFoundError)) {
		t.Errorf("getUserFactors error = %v (%T); want a notFoundError", err, err)
	}
}

// TestGetUsersWaitsForRateLimitReset checks that a 429 is retried after
// the time in X-Rate-Limit-Reset without counting as an attempt, even
// with a fixed rate limit, which ignores the rate limit headers.
func TestGetUsersWaitsForRateLimitReset(t *testing.T) {
	setFastRetry(t)
	retryPolicy.Attempts = 1
	var (
		calls atomic.Int32
		reset = time.Now().Add(3 * time.Second).Truncate(time.Second)
	)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("X-Rate-Limit-Reset", strconv.FormatInt(reset.Unix(), 10))
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"errorSummary":"too many requests"}`)
			return
		}
		_, _ = io.WriteString(w, `[{"id":"u1","status":"ACTIVE"}]`)
	}))
	defer srv.Close()

	_, _, err := getUsers(t.Context(), srv.Client(), srv.Listener.Addr().String(), "key", nil, OmitNone, fastLimiter(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("getUsers: %v", err)
	}
	if now := time.Now(); now.Before(reset) {
		t.Errorf("retried %v before the reset time", reset.Sub(now))
	}
}

func TestResetWait(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	unix := func(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }
	tests := []struct {
		name  string
		reset string
		date  string
		want  time.Duration
	}{
		{name: "no_header", want: 0},
		{name: "bad_header", reset: "soon", want: 0},
		{name: "past", reset: unix(now.Add(-time.Minute)), want: 0},
		{name: "ahead", reset: unix(now.Add(time.Minute)), want: time.Minute},
		{name: "capped", reset: unix(now.Add(48 * time.Hour)), want: maxWait},
		// The local clock is an hour ahead of the server's; the server's
		// Date header gives the right wait.
		{name: "server_date", reset: unix(now.Add(-time.Hour + time.Minute)), date: now.Add(-time.Hour).Format(http.TimeFormat), want: time.Minute},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.reset != "" {
				h.Set("X-Rate-Limit-Reset", tc.reset)
			}
			if tc.date != "" {
				h.Set("Date", tc.date)
			}
			if got := resetWait(h, now); got != tc.want {
				t.Errorf("resetWait = %v; want %v", got, tc.want)
			}
		})
	}
}

// TestGetUsersBadRateLimitHeader checks that a rate limit header the
// limiter cannot parse ends the request without retries.
func TestGetUsersBadRateLimitHeader(t *testing.T) {
	setFastRetry(t)
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("X-Rate-Limit-Limit", "many")
		w.Header().Set("X-Rate-Limit-Remaining", "1")
		w.Header().Set("X-Rate-Limit-Reset", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	// A dynamic limiter, so the headers are parsed.
	lim := NewRateLimiter(time.Minute, nil)
	_, _, err := getUsers(t.Context(), srv.Client(), srv.Listener.Addr().String(), "key", nil, OmitNone, lim, slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatal("getUsers succeeded; want a header parse error")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("server got %d requests; want 1", got)
	}
}

// TestEnrichmentRetryBudget checks that when an enrichment endpoint keeps
// failing, only the provider's retry budget is spent on retries, not a
// full set of retries for every user.
func TestEnrichmentRetryBudget(t *testing.T) {
	setFastRetry(t)
	unavailable := func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "unavailable")
	}
	tests := []struct {
		kind string
		// failing is the path suffix of the request that keeps failing.
		failing string
		// enrich is the enrichment to request.
		enrich map[string]bool
	}{
		{kind: "factors", failing: "/factors", enrich: map[string]bool{"factors": true}},
		{kind: "roles", failing: "/roles", enrich: map[string]bool{"roles": true}},
		{kind: "devices", failing: "/devices", enrich: map[string]bool{"devices": true}},
		{kind: "permissions", failing: "/permissions", enrich: map[string]bool{"roles": true, "permissions": true}},
	}
	for _, tc := range tests {
		t.Run(tc.kind, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, tc.failing) {
					calls.Add(1)
					unavailable(w)
					return
				}
				// A custom role for each user, so permissions are
				// requested for every user.
				id := path.Base(path.Dir(r.URL.Path))
				_, _ = fmt.Fprintf(w, `[{"id":"ra-%s","role":"cr-%s","type":"CUSTOM"}]`, id, id)
			}))
			defer srv.Close()

			cfg := DefaultConfig()
			cfg.Domain = srv.Listener.Addr().String()
			p := NewWithClient(cfg, srv.Client())
			const users = 30
			var skipped skippedEnrichment
			for i := range users {
				u := &User{ID: fmt.Sprintf("u%d", i)}
				err := p.enrichUser(t.Context(), srv.Client(), "key", fastLimiter(), slog.New(slog.DiscardHandler), tc.enrich, map[string][]Permission{}, &skipped, u, map[string]any{})
				if err != nil {
					t.Fatalf("enrichUser(%s): %v", u.ID, err)
				}
			}
			if got, want := calls.Load(), int32(users+enrichRetryLimit); got != want {
				t.Errorf("server got %d failing requests for %d users; want %d (one each plus the %d-retry budget)", got, users, want, enrichRetryLimit)
			}
			var incomplete *entcollect.IncompleteError
			err := skipped.err()
			switch {
			case !errors.As(err, &incomplete):
				t.Errorf("skipped.err() = %v; want *entcollect.IncompleteError", err)
			case !strings.Contains(err.Error(), fmt.Sprintf("%d enrichment requests failed", users)):
				t.Errorf("skipped.err() = %q; want it to count %d failures", err, users)
			case !strings.Contains(err.Error(), "first: "+tc.kind+" for "):
				t.Errorf("skipped.err() = %q; want it to name the first failure", err)
			}
			if tc.kind != "permissions" && !strings.Contains(err.Error(), "for user u0:") {
				t.Errorf("skipped.err() = %q; want the first failure to be user u0", err)
			}
		})
	}
}

// TestPermissionsOnlyForCustomRoles checks that permissions are requested
// only for custom roles.
func TestPermissionsOnlyForCustomRoles(t *testing.T) {
	var perms []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/permissions") {
			perms = append(perms, r.URL.Path)
			_, _ = io.WriteString(w, `{"permissions":[]}`)
			return
		}
		_, _ = io.WriteString(w, `[{"id":"ra1","type":"SUPER_ADMIN"},{"id":"ra2","role":"cr1","type":"CUSTOM"}]`)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.Domain = srv.Listener.Addr().String()
	p := NewWithClient(cfg, srv.Client())
	var skipped skippedEnrichment
	err := p.enrichUser(t.Context(), srv.Client(), "key", fastLimiter(), slog.New(slog.DiscardHandler), map[string]bool{"roles": true, "permissions": true}, map[string][]Permission{}, &skipped, &User{ID: "u1"}, map[string]any{})
	if err != nil {
		t.Fatalf("enrichUser: %v", err)
	}
	if want := []string{"/api/v1/iam/roles/cr1/permissions"}; !slices.Equal(perms, want) {
		t.Errorf("permissions requests = %v; want %v", perms, want)
	}
}

// TestDeviceUsersFullRetries checks that device user requests, whose
// failure ends the sync, are not limited by the enrichment budget.
func TestDeviceUsersFullRetries(t *testing.T) {
	setFastRetry(t)
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < int32(retryPolicy.Attempts) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, `[]`)
	}))
	defer srv.Close()

	_, _, err := getDeviceUsers(t.Context(), srv.Client(), srv.Listener.Addr().String(), "key", "d1", nil, OmitNone, fastLimiter(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Errorf("getDeviceUsers: %v", err)
	}
}

func TestResponseError(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "empty", body: "", want: "403 Forbidden: empty response body"},
		{name: "okta", body: `{"errorCode":"E0000006","errorSummary":"You do not have permission."}`, want: "403 Forbidden: you do not have permission"},
		{name: "other_json", body: `{"message":"nope"}`, want: `403 Forbidden: {"message":"nope"}`},
		{name: "html", body: "<html>Forbidden</html>", want: "403 Forbidden: <html>Forbidden</html>"},
		{name: "long", body: strings.Repeat("x", 300), want: "403 Forbidden: " + strings.Repeat("x", 256) + "..."},
	}
	for _, tc := range tests {
		if got := responseError("403 Forbidden", []byte(tc.body)).Error(); got != tc.want {
			t.Errorf("%s: responseError = %q; want %q", tc.name, got, tc.want)
		}
	}
}

// TestRateLimiterWaitNotRetried checks that a rate limiter that cannot
// grant a request in time ends the request without retries.
func TestRateLimiterWaitNotRetried(t *testing.T) {
	setFastRetry(t)
	var calls atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		// One request left for two hours: the limiter cannot grant the
		// next within its 30 minute limit.
		w.Header().Set("X-Rate-Limit-Limit", "1")
		w.Header().Set("X-Rate-Limit-Remaining", "1")
		w.Header().Set("X-Rate-Limit-Reset", strconv.FormatInt(time.Now().Add(2*time.Hour).Unix(), 10))
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	_, _, err := getUsers(ctx, srv.Client(), srv.Listener.Addr().String(), "key", nil, OmitNone, NewRateLimiter(time.Minute, nil), slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatal("getUsers succeeded; want a rate limiter error")
	}
	if errors.As(err, new(*httpretry.Error)) {
		t.Errorf("getUsers error = %v; want the limiter's error, not retries", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("server got %d requests; want 1", got)
	}
}

// setFastRetry shortens the retry delays for the duration of the test.
func setFastRetry(t *testing.T) {
	old := retryPolicy
	retryPolicy = httpretry.Policy{Attempts: old.Attempts, BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond}
	t.Cleanup(func() { retryPolicy = old })
}

// fastLimiter returns a rate limiter that does not slow the test.
func fastLimiter() *RateLimiter {
	n := 1000
	return NewRateLimiter(time.Second, &n)
}

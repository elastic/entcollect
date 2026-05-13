// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package okta

import (
	"log/slog"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestRateLimiter_EndpointSeparation(t *testing.T) {
	r := NewRateLimiter(time.Minute, nil)
	e1 := r.endpoint("/foo")
	e2 := r.endpoint("/bar")

	e1.limiter.SetBurst(1000)

	if e2.limiter.Burst() == 1000 {
		t.Errorf("changes to one endpoint's limits affected another")
	}
}

func TestRateLimiter_FixedLimit(t *testing.T) {
	fixed := 100
	r := NewRateLimiter(time.Minute, &fixed)

	log := slog.New(slog.NewTextHandler(&discardWriter{}, nil))
	headers := http.Header{
		"X-Rate-Limit-Limit":     {"60"},
		"X-Rate-Limit-Remaining": {"30"},
		"X-Rate-Limit-Reset":     {strconv.FormatInt(time.Now().Add(30*time.Second).Unix(), 10)},
	}

	if err := r.Update("/foo", headers, log); err != nil {
		t.Fatalf("Update: %v", err)
	}

	e := r.endpoint("/foo")
	// With fixed limit, the rate should be fixed/window = 100/60.
	expectedRate := float64(fixed) / time.Minute.Seconds()
	if float64(e.limiter.Limit()) != expectedRate {
		t.Errorf("limit = %f; want %f (fixed limit should override headers)", float64(e.limiter.Limit()), expectedRate)
	}
}

func TestRateLimiter_UpdateFromHeaders(t *testing.T) {
	r := NewRateLimiter(time.Minute, nil)
	log := slog.New(slog.NewTextHandler(&discardWriter{}, nil))

	resetTime := time.Now().Add(30 * time.Second)
	headers := http.Header{
		"X-Rate-Limit-Limit":     {"60"},
		"X-Rate-Limit-Remaining": {"30"},
		"X-Rate-Limit-Reset":     {strconv.FormatInt(resetTime.Unix(), 10)},
	}

	if err := r.Update("/test", headers, log); err != nil {
		t.Fatalf("Update: %v", err)
	}

	e := r.endpoint("/test")
	// Rate should be remaining/seconds_until_reset = 30/~30 ≈ 1.0
	if e.limiter.Limit() <= 0 {
		t.Errorf("limit = %f; want > 0", float64(e.limiter.Limit()))
	}
}

func TestRateLimiter_MissingHeaders(t *testing.T) {
	r := NewRateLimiter(time.Minute, nil)
	log := slog.New(slog.NewTextHandler(&discardWriter{}, nil))

	// Missing all headers — should be a no-op.
	if err := r.Update("/test", http.Header{}, log); err != nil {
		t.Fatalf("Update: %v", err)
	}

	e := r.endpoint("/test")
	if e.limiter.Limit() != 1 {
		t.Errorf("limit = %f; want 1 (default)", float64(e.limiter.Limit()))
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

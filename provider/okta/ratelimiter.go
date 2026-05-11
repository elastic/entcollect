// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package okta

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter holds per-endpoint rate limiting state for the Okta API.
//
// Each API endpoint has its own rate limit, dynamically updated from
// response headers. If a fixed limit is set, it overrides API response
// guidance.
type RateLimiter struct {
	window     time.Duration
	fixedLimit *int
	byEndpoint map[string]endpointRateLimiter
}

type endpointRateLimiter struct {
	limiter *rate.Limiter
	ready   chan struct{}
}

// maxWait defines the longest wait the rate limiter will allow before
// returning an error.
const maxWait = 30 * time.Minute

// NewRateLimiter constructs a RateLimiter. window is the time between
// API limit resets. fixedLimit, if non-nil, overrides dynamic rate
// computation from response headers.
func NewRateLimiter(window time.Duration, fixedLimit *int) *RateLimiter {
	return &RateLimiter{
		window:     window,
		fixedLimit: fixedLimit,
		byEndpoint: make(map[string]endpointRateLimiter),
	}
}

// Update reads X-Rate-Limit-* headers and adjusts the rate for endpoint.
//
// See https://developer.okta.com/docs/reference/rl-best-practices/ for details.
func (r *RateLimiter) Update(endpoint string, h http.Header, log *slog.Logger) error {
	if r.fixedLimit != nil {
		return nil
	}
	e := r.endpoint(endpoint)
	limit := h.Get("X-Rate-Limit-Limit")
	remaining := h.Get("X-Rate-Limit-Remaining")
	reset := h.Get("X-Rate-Limit-Reset")
	log.Debug("rate limit header", "X-Rate-Limit-Limit", limit, "X-Rate-Limit-Remaining", remaining, "X-Rate-Limit-Reset", reset)
	if limit == "" || remaining == "" || reset == "" {
		return nil
	}

	lim, err := strconv.ParseFloat(limit, 64)
	if err != nil {
		return err
	}
	rem, err := strconv.ParseFloat(remaining, 64)
	if err != nil {
		return err
	}
	rst, err := strconv.ParseInt(reset, 10, 64)
	if err != nil {
		return err
	}
	resetTime := time.Unix(rst, 0)
	per := time.Until(resetTime).Seconds()

	burst := 1
	rateLimit := rate.Limit(rem / per)

	if rateLimit <= 0 {
		limiter := rate.NewLimiter(0, 0)
		ready := make(chan struct{})
		r.byEndpoint[endpoint] = endpointRateLimiter{
			limiter: limiter,
			ready:   ready,
		}

		var next rate.Limit
		if lim == 0 {
			log.Debug("exceeded the concurrent rate limit")
			next = rate.Limit(1)
		} else {
			next = rate.Limit(lim / r.window.Seconds())
		}

		resetTimeUTC := resetTime.UTC()
		log.Debug("rate limit block until reset", "reset_time", resetTimeUTC)
		waitFor := time.Until(resetTimeUTC)

		time.AfterFunc(waitFor, func() {
			limiter.SetLimit(next)
			limiter.SetBurst(burst)
			close(ready)
			log.Debug("rate limit reset", "reset_time", resetTimeUTC, "reset_rate", next, "reset_burst", burst)
		})

		return nil
	}
	e.limiter.SetLimit(rateLimit)
	e.limiter.SetBurst(burst)
	log.Debug("rate limit adjust", "set_rate", rateLimit, "set_burst", burst)
	return nil
}

// Wait blocks until the rate limiter allows a request to the given endpoint.
func (r *RateLimiter) Wait(ctx context.Context, endpoint string) error {
	e := r.endpoint(endpoint)
	ctxWithDeadline, cancel := context.WithDeadline(ctx, time.Now().Add(maxWait))
	defer cancel()
	select {
	case <-e.ready:
	case <-ctxWithDeadline.Done():
		return ctxWithDeadline.Err()
	}
	return e.limiter.Wait(ctxWithDeadline)
}

var immediatelyReady = make(chan struct{})

func init() { close(immediatelyReady) }

func (r *RateLimiter) endpoint(path string) endpointRateLimiter {
	if existing, ok := r.byEndpoint[path]; ok {
		return existing
	}
	limit := rate.Limit(1)
	if r.fixedLimit != nil {
		limit = rate.Limit(float64(*r.fixedLimit) / r.window.Seconds())
	}
	e := endpointRateLimiter{
		limiter: rate.NewLimiter(limit, 1),
		ready:   immediatelyReady,
	}
	r.byEndpoint[path] = e
	return e
}

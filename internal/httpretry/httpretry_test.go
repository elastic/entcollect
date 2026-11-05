// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package httpretry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var testPolicy = Policy{Attempts: 3, BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond}

func TestDoRetriesTransientFailures(t *testing.T) {
	ok := func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `[]`)
	}
	tests := []struct {
		name string
		// fail writes the response for the first attempt.
		fail func(w http.ResponseWriter)
	}{
		{name: "server_error", fail: func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "unavailable")
		}},
		{name: "too_many_requests", fail: func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, "slow down")
		}},
		{name: "empty_body", fail: func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusOK)
		}},
		{name: "truncated_body", fail: func(w http.ResponseWriter) {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `[{"id":`)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					tc.fail(w)
					return
				}
				ok(w)
			}))
			defer srv.Close()

			resp, err := Do(t.Context(), testPolicy, slog.New(slog.DiscardHandler), get(srv.Client(), srv.URL))
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			if resp.StatusCode != http.StatusOK || string(resp.Body) != `[]` {
				t.Errorf("Do = %d %q; want 200 []", resp.StatusCode, resp.Body)
			}
			if got := calls.Load(); got != 2 {
				t.Errorf("server got %d requests; want 2", got)
			}
		})
	}
}

func TestDoRetriesClientTimeout(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
			return
		}
		_, _ = io.WriteString(w, `[]`)
	}))
	defer srv.Close()
	cli := srv.Client()
	cli.Timeout = 250 * time.Millisecond

	resp, err := Do(t.Context(), testPolicy, slog.New(slog.DiscardHandler), get(cli, srv.URL))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if string(resp.Body) != `[]` {
		t.Errorf("Do body = %q; want []", resp.Body)
	}
}

func TestDoReturnsOtherStatuses(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"errorCode":"E0000007"}`)
	}))
	defer srv.Close()

	resp, err := Do(t.Context(), testPolicy, slog.New(slog.DiscardHandler), get(srv.Client(), srv.URL))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Do status = %d; want 404", resp.StatusCode)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("server got %d requests; want 1", got)
	}
}

func TestDoReturnsEmptyClientError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	resp, err := Do(t.Context(), testPolicy, slog.New(slog.DiscardHandler), get(srv.Client(), srv.URL))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized || len(resp.Body) != 0 {
		t.Errorf("Do = %d %q; want 401 with an empty body", resp.StatusCode, resp.Body)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("server got %d requests; want 1", got)
	}
}

func TestBackoff(t *testing.T) {
	p := Policy{BaseDelay: time.Second, MaxDelay: 30 * time.Second}
	for attempt, want := range map[int]time.Duration{
		1:   time.Second,
		2:   2 * time.Second,
		5:   16 * time.Second,
		6:   30 * time.Second,
		40:  30 * time.Second,
		100: 30 * time.Second,
	} {
		if got := backoff(attempt, p); got != want {
			t.Errorf("backoff(%d) = %v; want %v", attempt, got, want)
		}
	}
}

func TestDoNoContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	resp, err := Do(t.Context(), testPolicy, slog.New(slog.DiscardHandler), get(srv.Client(), srv.URL))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("Do status = %d; want 204", resp.StatusCode)
	}
}

func TestDoExhausted(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "upstream down")
	}))
	defer srv.Close()

	_, err := Do(t.Context(), testPolicy, slog.New(slog.DiscardHandler), get(srv.Client(), srv.URL))
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("Do error = %v (%T); want *Error", err, err)
	}
	if e.StatusCode != http.StatusBadGateway {
		t.Errorf("Error.StatusCode = %d; want 502", e.StatusCode)
	}
	if want := "all 3 attempts failed: 502 Bad Gateway: upstream down"; err.Error() != want {
		t.Errorf("Do error = %q; want %q", err, want)
	}
	if got := calls.Load(); got != int32(testPolicy.Attempts) {
		t.Errorf("server got %d requests; want %d", got, testPolicy.Attempts)
	}
}

func TestDoHonoursRetryAfter(t *testing.T) {
	var (
		calls atomic.Int32
		// first is safe to share: the client sends the second request only
		// after it has read the first response.
		first time.Time
		gaps  = make(chan time.Duration, 1)
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			first = time.Now()
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, "slow down")
			return
		}
		gaps <- time.Since(first)
		_, _ = io.WriteString(w, `[]`)
	}))
	defer srv.Close()

	// The wait is not capped at MaxDelay, and the retry is not counted, so
	// one attempt is enough.
	p := Policy{Attempts: 1, BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond}
	_, err := Do(t.Context(), p, slog.New(slog.DiscardHandler), get(srv.Client(), srv.URL))
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if gap := <-gaps; gap < time.Second {
		t.Errorf("retried after %v; want at least the 1s Retry-After", gap)
	}
}

// TestDoServerErrorRetryAfter checks that a 5xx response's Retry-After
// lengthens the backoff, up to MaxDelay.
func TestDoServerErrorRetryAfter(t *testing.T) {
	p := Policy{Attempts: 2, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Second}
	var calls atomic.Int32
	start := time.Now()
	_, err := Do(t.Context(), p, slog.New(slog.DiscardHandler), func(context.Context) (*http.Response, error) {
		if calls.Add(1) == 1 {
			resp := fakeResponse(http.StatusServiceUnavailable, "unavailable")
			resp.Header.Set("Retry-After", "1")
			return resp, nil
		}
		return fakeResponse(http.StatusOK, "[]"), nil
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if d := time.Since(start); d < time.Second {
		t.Errorf("retried after %v; want at least the 1s Retry-After", d)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		value string
		want  time.Duration
	}{
		{value: "", want: 0},
		{value: "30", want: 30 * time.Second},
		{value: "-5", want: 0},
		{value: "soon", want: 0},
		{value: now.Add(90 * time.Second).Format(http.TimeFormat), want: 90 * time.Second},
		{value: now.Add(-time.Minute).Format(http.TimeFormat), want: 0},
		{value: "100000000000", want: time.Duration(math.MaxInt64 / int64(time.Second) * int64(time.Second))},
	}
	for _, tc := range tests {
		if got := parseRetryAfter(tc.value, now); got != tc.want {
			t.Errorf("parseRetryAfter(%q) = %v; want %v", tc.value, got, tc.want)
		}
	}
}

func TestDoContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "unavailable")
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(t.Context())
	var calls atomic.Int32
	send := func(ctx context.Context) (*http.Response, error) {
		resp, err := get(srv.Client(), srv.URL)(ctx)
		if err == nil {
			// Buffer the body so cancellation cannot interrupt reading it,
			// and Do sees the cancellation while waiting to retry.
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			resp.Body = io.NopCloser(bytes.NewReader(body))
		}
		if calls.Add(1) == 1 {
			// Cancel once the response is in, so Do sees the
			// cancellation while waiting to retry.
			cancel()
		}
		return resp, err
	}
	// A long delay, so only cancellation can end the wait.
	p := Policy{Attempts: 3, BaseDelay: time.Hour, MaxDelay: time.Hour}
	_, err := Do(ctx, p, slog.New(slog.DiscardHandler), send)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Do error = %v; want it to wrap context.Canceled", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("send called %d times; want 1", got)
	}
}

func TestDoPermanent(t *testing.T) {
	errBad := errors.New("bad request")
	var calls atomic.Int32
	_, err := Do(t.Context(), testPolicy, slog.New(slog.DiscardHandler), func(context.Context) (*http.Response, error) {
		calls.Add(1)
		return nil, Permanent(errBad)
	})
	if err != errBad {
		t.Errorf("Do error = %v; want %v", err, errBad)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("send called %d times; want 1", got)
	}
}

// get returns a send function that makes a GET request to url with cli.
func get(cli *http.Client, url string) func(context.Context) (*http.Response, error) {
	return func(ctx context.Context) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, Permanent(err)
		}
		return cli.Do(req)
	}
}

func TestDoMinimumOneAttempt(t *testing.T) {
	var calls atomic.Int32
	_, err := Do(t.Context(), Policy{}, slog.New(slog.DiscardHandler), func(context.Context) (*http.Response, error) {
		calls.Add(1)
		return fakeResponse(http.StatusServiceUnavailable, ""), nil
	})
	if want := "1 attempt failed: 503 Service Unavailable"; err == nil || err.Error() != want {
		t.Errorf("Do error = %v; want %q", err, want)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("send called %d times; want 1", got)
	}
}

func TestDoCapsRetryAfter(t *testing.T) {
	var calls atomic.Int32
	p := Policy{Attempts: 2, BaseDelay: time.Millisecond, MaxDelay: 50 * time.Millisecond}
	// Without the cap, Do waits an hour and the deadline ends it.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	start := time.Now()
	_, err := Do(ctx, p, slog.New(slog.DiscardHandler), func(context.Context) (*http.Response, error) {
		if calls.Add(1) == 1 {
			resp := fakeResponse(http.StatusServiceUnavailable, "unavailable")
			resp.Header.Set("Retry-After", "3600")
			return resp, nil
		}
		return fakeResponse(http.StatusOK, "[]"), nil
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Do took %v; want the Retry-After wait capped at %v", d, p.MaxDelay)
	}
}

// TestDoLimitsErrorBody checks that only the start of a retried body is
// kept, and that the rest is read so the connection is reused.
func TestDoLimitsErrorBody(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, strings.Repeat("x", 10<<10))
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	_, err := Do(t.Context(), testPolicy, slog.New(slog.DiscardHandler), get(srv.Client(), srv.URL))
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("Do error = %v; want *Error", err)
	}
	if want := "500 Internal Server Error: " + strings.Repeat("x", errorBodyLimit); e.Err.Error() != want {
		t.Errorf("last error has %d bytes; want %d", len(e.Err.Error()), len(want))
	}
	if got := conns.Load(); got != 1 {
		t.Errorf("server saw %d connections for %d requests; want 1", got, testPolicy.Attempts)
	}
}

func TestDoContextErrors(t *testing.T) {
	errBad := errors.New("bad request")
	tests := []struct {
		name string
		// send is called with cancel, and cancels the context itself.
		send func(ctx context.Context, cancel func()) (*http.Response, error)
		// want is the error Do must return, if not one wrapping
		// context.Canceled.
		want error
	}{
		{
			name: "send_error",
			send: func(ctx context.Context, cancel func()) (*http.Response, error) {
				cancel()
				return nil, fmt.Errorf("get: %w", ctx.Err())
			},
		},
		{
			name: "permanent_first",
			send: func(ctx context.Context, cancel func()) (*http.Response, error) {
				cancel()
				return nil, Permanent(errBad)
			},
			want: errBad,
		},
		{
			name: "body_read",
			send: func(ctx context.Context, cancel func()) (*http.Response, error) {
				resp := fakeResponse(http.StatusOK, "")
				resp.Body = io.NopCloser(readerFunc(func([]byte) (int, error) {
					cancel()
					return 0, io.ErrUnexpectedEOF
				}))
				return resp, nil
			},
		},
		{
			name: "last_attempt",
			send: func(ctx context.Context, cancel func()) (*http.Response, error) {
				cancel()
				return fakeResponse(http.StatusServiceUnavailable, "unavailable"), nil
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var calls atomic.Int32
			_, err := Do(ctx, Policy{Attempts: 1}, slog.New(slog.DiscardHandler), func(ctx context.Context) (*http.Response, error) {
				calls.Add(1)
				return tc.send(ctx, cancel)
			})
			if tc.want != nil {
				if err != tc.want {
					t.Errorf("Do error = %v; want %v", err, tc.want)
				}
				return
			}
			if !errors.Is(err, context.Canceled) {
				t.Errorf("Do error = %v; want it to wrap context.Canceled", err)
			}
			if n := strings.Count(fmt.Sprint(err), context.Canceled.Error()); n != 1 {
				t.Errorf("Do error = %q mentions cancellation %d times; want once", err, n)
			}
			if got := calls.Load(); got != 1 {
				t.Errorf("send called %d times; want 1", got)
			}
		})
	}
}

func TestDoUnrecoverableTransportErrors(t *testing.T) {
	tests := []struct {
		name string
		srv  func() *httptest.Server
	}{
		{name: "untrusted_certificate", srv: func() *httptest.Server {
			return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		}},
		{name: "redirect_loop", srv: func() *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, r.URL.Path, http.StatusFound)
			}))
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := tc.srv()
			defer srv.Close()
			var calls atomic.Int32
			send := get(&http.Client{}, srv.URL)
			_, err := Do(t.Context(), testPolicy, slog.New(slog.DiscardHandler), func(ctx context.Context) (*http.Response, error) {
				calls.Add(1)
				return send(ctx)
			})
			if err == nil {
				t.Fatal("Do succeeded; want an error")
			}
			if got := calls.Load(); got != 1 {
				t.Errorf("send called %d times; want 1 (error: %v)", got, err)
			}
		})
	}
}

// fakeResponse returns a response with the given status and body.
func fakeResponse(code int, body string) *http.Response {
	return &http.Response{
		StatusCode: code,
		Status:     fmt.Sprintf("%d %s", code, http.StatusText(code)),
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func TestBudget(t *testing.T) {
	b := NewBudget(2, time.Minute)
	start := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	steps := []struct {
		after time.Duration
		want  bool
	}{
		{after: 0, want: true},
		{after: 10 * time.Second, want: true},
		{after: 20 * time.Second, want: false},
		{after: 60 * time.Second, want: true},  // the first retry has left the window
		{after: 65 * time.Second, want: false}, // the second has not
		{after: 70 * time.Second, want: true},
	}
	for _, step := range steps {
		if got := b.take(start.Add(step.after)); got != step.want {
			t.Errorf("take at +%v = %t; want %t", step.after, got, step.want)
		}
	}

	var nilBudget *Budget
	if !nilBudget.take(start) {
		t.Error("nil Budget refused a retry")
	}
}

func TestDoBudgetExhausted(t *testing.T) {
	var calls atomic.Int32
	send := func(context.Context) (*http.Response, error) {
		calls.Add(1)
		return fakeResponse(http.StatusServiceUnavailable, "unavailable"), nil
	}
	p := testPolicy
	p.Budget = NewBudget(2, time.Hour)

	// The first call spends the whole budget on its two retries.
	_, err := Do(t.Context(), p, slog.New(slog.DiscardHandler), send)
	if errors.Is(err, ErrBudgetExhausted) {
		t.Errorf("first Do error = %v; want attempts to run out before the budget", err)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("first Do sent %d requests; want 3", got)
	}

	calls.Store(0)
	_, err = Do(t.Context(), p, slog.New(slog.DiscardHandler), send)
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Errorf("second Do error = %v; want it to wrap ErrBudgetExhausted", err)
	}
	if want := "1 attempt failed: retry budget exhausted: 503 Service Unavailable: unavailable"; err == nil || err.Error() != want {
		t.Errorf("second Do error = %q; want %q", err, want)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("second Do sent %d requests; want 1", got)
	}
}

// TestDoBareRateLimitSpendsBudget checks that a 429 that gives no wait
// is treated as a failed attempt.
func TestDoBareRateLimitSpendsBudget(t *testing.T) {
	p := testPolicy
	p.Budget = NewBudget(1, time.Hour)
	var calls atomic.Int32
	_, err := Do(t.Context(), p, slog.New(slog.DiscardHandler), func(context.Context) (*http.Response, error) {
		calls.Add(1)
		return fakeResponse(http.StatusTooManyRequests, "slow down"), nil
	})
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Errorf("Do error = %v; want it to wrap ErrBudgetExhausted", err)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("send called %d times; want 2", got)
	}
}

func TestDoPacer(t *testing.T) {
	errPacer := errors.New("pacer failed")
	tests := []struct {
		name       string
		retryAfter string
		pacer      *fakePacer
		wantErr    bool
		wantErrIs  error
		// wantErrText, if set, must appear in the error.
		wantErrText string
		wantPacer   int
	}{
		{name: "paced", pacer: &fakePacer{ok: true}, wantPacer: 1},
		{name: "no_pace", pacer: &fakePacer{ok: false}, wantErr: true, wantErrText: "429 Too Many Requests: slow down", wantPacer: 1},
		{name: "pacer_error", pacer: &fakePacer{err: errPacer}, wantErr: true, wantErrIs: errPacer, wantPacer: 1},
		{name: "retry_after_wins", retryAfter: "1", pacer: &fakePacer{ok: false}, wantPacer: 0},
		{name: "zero_retry_after", retryAfter: "0", pacer: &fakePacer{ok: true}, wantPacer: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// One attempt and no budget: only a retry that is neither
			// counted nor charged can succeed.
			p := Policy{Attempts: 1, BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond, Budget: NewBudget(0, time.Hour), Pacer: tc.pacer}
			var calls atomic.Int32
			_, err := Do(t.Context(), p, slog.New(slog.DiscardHandler), func(context.Context) (*http.Response, error) {
				if calls.Add(1) == 1 {
					resp := fakeResponse(http.StatusTooManyRequests, "slow down")
					if tc.retryAfter != "" {
						resp.Header.Set("Retry-After", tc.retryAfter)
					}
					return resp, nil
				}
				return fakeResponse(http.StatusOK, "[]"), nil
			})
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Errorf("Do error = %v; want error %t", err, tc.wantErr)
			}
			if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
				t.Errorf("Do error = %v; want it to wrap %v", err, tc.wantErrIs)
			}
			if tc.wantErrText != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErrText)) {
				t.Errorf("Do error = %v; want it to contain %q", err, tc.wantErrText)
			}
			if got := tc.pacer.calls; got != tc.wantPacer {
				t.Errorf("pacer called %d times; want %d", got, tc.wantPacer)
			}
		})
	}
}

// TestDoPacedAfterFailure checks that a paced retry following a counted
// failure does not spend the budget.
func TestDoPacedAfterFailure(t *testing.T) {
	p := Policy{Attempts: 2, BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond, Budget: NewBudget(1, time.Hour), Pacer: &fakePacer{ok: true}}
	var calls atomic.Int32
	_, err := Do(t.Context(), p, slog.New(slog.DiscardHandler), func(context.Context) (*http.Response, error) {
		switch calls.Add(1) {
		case 1:
			return fakeResponse(http.StatusServiceUnavailable, "unavailable"), nil
		case 2:
			return fakeResponse(http.StatusTooManyRequests, "slow down"), nil
		}
		return fakeResponse(http.StatusOK, "[]"), nil
	})
	if err != nil {
		t.Errorf("Do: %v", err)
	}
}

func TestDoMaxPaced(t *testing.T) {
	tests := []struct {
		name      string
		maxPaced  int
		wantCalls int32
	}{
		{name: "default", maxPaced: 0, wantCalls: defaultMaxPaced + 1},
		{name: "three", maxPaced: 3, wantCalls: 4},
		{name: "none", maxPaced: -1, wantCalls: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pacer := &fakePacer{ok: true}
			p := Policy{Attempts: 1, MaxPaced: tc.maxPaced, Pacer: pacer}
			var calls atomic.Int32
			_, err := Do(t.Context(), p, slog.New(slog.DiscardHandler), func(context.Context) (*http.Response, error) {
				calls.Add(1)
				return fakeResponse(http.StatusTooManyRequests, "slow down"), nil
			})
			var e *Error
			if !errors.As(err, &e) || e.StatusCode != http.StatusTooManyRequests {
				t.Errorf("Do error = %v; want *Error with status 429", err)
			}
			if got := calls.Load(); got != tc.wantCalls {
				t.Errorf("send called %d times; want %d", got, tc.wantCalls)
			}
		})
	}
}

// TestDoPacingCancelled checks that cancellation while pacing returns an
// error that wraps context.Canceled and names the 429.
func TestDoPacingCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	p := Policy{Attempts: 1, Pacer: blockingPacer{cancel: cancel}}
	_, err := Do(ctx, p, slog.New(slog.DiscardHandler), func(context.Context) (*http.Response, error) {
		return fakeResponse(http.StatusTooManyRequests, "slow down"), nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Do error = %v; want it to wrap context.Canceled", err)
	}
	if err == nil || !strings.Contains(err.Error(), "429 Too Many Requests: slow down") {
		t.Errorf("Do error = %v; want it to name the 429", err)
	}
}

func TestRetryAfterWait(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{
		{value: "", want: 0},
		{value: "120", want: 2 * time.Minute},
		{value: "86400", want: maxPaceWait},
	} {
		h := http.Header{}
		if tc.value != "" {
			h.Set("Retry-After", tc.value)
		}
		if got := retryAfterWait(h, now); got != tc.want {
			t.Errorf("retryAfterWait(%q) = %v; want %v", tc.value, got, tc.want)
		}
	}
}

// blockingPacer cancels the context, then waits for it to be done.
type blockingPacer struct{ cancel func() }

func (p blockingPacer) Wait(ctx context.Context, _ *http.Response) (bool, error) {
	p.cancel()
	<-ctx.Done()
	return false, ctx.Err()
}

// fakePacer is a Pacer that returns fixed results without waiting.
type fakePacer struct {
	ok    bool
	err   error
	calls int
}

func (p *fakePacer) Wait(context.Context, *http.Response) (bool, error) {
	p.calls++
	return p.ok, p.err
}

// TestDoBudgetContextDone checks that a done context is reported even
// when the budget would refuse the retry.
func TestDoBudgetContextDone(t *testing.T) {
	p := testPolicy
	p.Budget = NewBudget(0, time.Hour)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	_, err := Do(ctx, p, slog.New(slog.DiscardHandler), func(context.Context) (*http.Response, error) {
		cancel()
		return fakeResponse(http.StatusServiceUnavailable, "unavailable"), nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Do error = %v; want it to wrap context.Canceled", err)
	}
}

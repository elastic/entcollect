// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package httpretry retries HTTP requests that fail for reasons that are
// likely to be transient.
//
// A request is retried after a transport error, including an HTTP client
// timeout, after a 429 or 5xx response, after a response whose body cannot
// be read in full, and after a 2xx response other than 204 with an empty
// body. It is not retried once the caller's context is done, or after a
// certificate verification failure or a redirect loop, which cannot
// succeed on a later attempt.
//
// After a 429 response, Do waits for as long as its Retry-After header
// asks, or, if the header is missing or gives no wait, as the Policy's
// Pacer decides. Such a paced retry is not counted as an attempt, up to
// Policy.MaxPaced of them in one call. A 429 that gives no wait, or one
// after the paced retries are used up, is handled like a 5xx response.
package httpretry

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrBudgetExhausted is wrapped by the error Do returns when it stopped
// because its retry budget was spent.
var ErrBudgetExhausted = errors.New("retry budget exhausted")

// Policy sets how many attempts are made and how long to wait between them.
type Policy struct {
	// Attempts is the maximum number of attempts, including the first.
	Attempts int
	// BaseDelay is the wait before the first retry. It doubles after
	// each further attempt.
	BaseDelay time.Duration
	// MaxDelay caps the wait between attempts, including a wait
	// requested by a Retry-After header on a response handled as a failed
	// attempt. It does not cap the wait before a paced retry after a 429
	// response (see MaxPaced). Zero or less means 30 minutes, the longest
	// wait Do takes before a paced retry.
	MaxDelay time.Duration
	// Budget, if not nil, limits the retries made by all the calls that
	// share it. When it is spent, a failed attempt is not retried.
	Budget *Budget
	// Pacer, if not nil, sets the wait after a 429 response whose
	// Retry-After header is missing or gives no wait.
	Pacer Pacer
	// MaxPaced is the most paced retries Do makes in one call: retries
	// after a 429 response, waiting as its Retry-After header or the
	// Pacer says. Paced retries are not counted as attempts and do not
	// spend the budget. Zero means 10; a negative value means none.
	MaxPaced int
}

// defaultMaxPaced is the number of paced retries when Policy.MaxPaced is
// zero.
const defaultMaxPaced = 10

// Pacer decides how long to wait after a 429 response before the request
// may be sent again. Servers signal how long to wait in many different
// ways, so a Pacer holds the knowledge of a particular server. Do does
// the waiting, caps the wait at 30 minutes, and limits how many times it
// paces one call (Policy.MaxPaced), so a Pacer need not. One Pacer can be
// shared by concurrent calls if its Delay is safe for concurrent use.
type Pacer interface {
	// Delay returns how long to wait after resp, a 429 response whose
	// body has been read and closed. It reports false if it cannot tell,
	// and Do then treats the 429 as a failed attempt.
	Delay(resp *http.Response) (time.Duration, bool)
}

// Budget limits the number of retries across calls to Do: at most limit
// retries within any period of window. It lets a caller keep retrying
// occasional failures while not retrying every one of many calls that
// fail for the same reason. A Budget is safe for concurrent use.
type Budget struct {
	limit  int
	window time.Duration

	mu sync.Mutex
	// retries holds the times of the retries in the last window, about
	// oldest first: concurrent callers may record them slightly out of
	// order, which can only keep a retry counted a little too long.
	retries []time.Time
}

// NewBudget returns a Budget that allows limit retries within any period
// of window. A limit of zero or less allows no retries, whatever the
// window. Otherwise, a window of zero or less allows any number.
func NewBudget(limit int, window time.Duration) *Budget {
	return &Budget{limit: limit, window: window}
}

// take reports whether a retry is allowed at now, and if so records it. A
// nil Budget allows every retry.
func (b *Budget) take(now time.Time) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	i := 0
	for i < len(b.retries) && now.Sub(b.retries[i]) >= b.window {
		i++
	}
	b.retries = b.retries[i:]
	if len(b.retries) >= b.limit {
		return false
	}
	b.retries = append(b.retries, now)
	return true
}

// Response is a response that was not retried, with its body read in full.
type Response struct {
	Status     string // e.g. "404 Not Found"
	StatusCode int
	Header     http.Header
	Body       []byte
}

// Error is returned when all attempts fail, or when a retry is needed but
// the retry budget is spent. It holds the status of the last response, if
// there was one, and the reason the last attempt failed.
type Error struct {
	Attempts   int
	StatusCode int // zero if the last attempt got no response
	Err        error
}

func (e *Error) Error() string {
	if e.Attempts == 1 {
		return fmt.Sprintf("1 attempt failed: %v", e.Err)
	}
	return fmt.Sprintf("all %d attempts failed: %v", e.Attempts, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// Permanent marks err as not worth retrying. When send returns an error
// wrapped by Permanent, Do returns err without further attempts.
func Permanent(err error) error {
	return permanentError{err}
}

type permanentError struct{ err error }

func (e permanentError) Error() string { return e.err.Error() }
func (e permanentError) Unwrap() error { return e.err }

// Do calls send until it returns a response that is not retried, up to
// p.Attempts times, or once if p.Attempts is less than one. send must be
// safe to call more than once. Do reads and closes the body of every
// response. Do returns the first response that is not retried, whatever
// its status, so the caller decides how to handle a status such as 404.
//
// If ctx is done, Do returns an error that wraps ctx.Err(). If all
// attempts fail, or a retry is needed but p.Budget is spent, it returns an
// *Error; in the second case the error wraps ErrBudgetExhausted.
func Do(ctx context.Context, p Policy, log *slog.Logger, send func(context.Context) (*http.Response, error)) (*Response, error) {
	attempts := max(p.Attempts, 1)
	maxPaced := p.MaxPaced
	if maxPaced == 0 {
		maxPaced = defaultMaxPaced
	}
	if p.MaxDelay <= 0 {
		p.MaxDelay = maxPaceWait
	}
	var failed, paced int
	for {
		o := classify(send(ctx))
		switch {
		case o.resp != nil:
			return o.resp, nil
		case o.permanent:
			return nil, o.err
		case ctx.Err() != nil:
			return nil, withContext(ctx, o.err)
		case o.unrecoverable:
			return nil, o.err
		}

		// A paced retry waits as the server says, so it is not counted
		// as an attempt and does not spend the budget.
		if o.limited != nil && paced < maxPaced {
			d, source, ok := paceDelay(p.Pacer, o)
			if ok {
				paced++
				log.Info("rate limited, waiting", "wait", d, "source", source)
				if err := wait(ctx, d); err != nil {
					return nil, withContext(ctx, o.err)
				}
				continue
			}
		}

		failed++
		if failed == attempts {
			return nil, &Error{Attempts: attempts, StatusCode: o.status, Err: o.err}
		}
		if !p.Budget.take(time.Now()) {
			return nil, &Error{Attempts: failed, StatusCode: o.status, Err: fmt.Errorf("%w: %w", ErrBudgetExhausted, o.err)}
		}
		d := max(backoff(failed, p), min(o.retryAfter, p.MaxDelay))
		log.Warn("retrying request", "retry", failed, "max", attempts, "backoff", d, "status", o.status, "error", o.err)
		if err := wait(ctx, d); err != nil {
			return nil, withContext(ctx, o.err)
		}
	}
}

// outcome is the result of one call to send.
type outcome struct {
	// resp is the response if it is not retried.
	resp *Response
	// err is why the attempt failed.
	err error
	// permanent is whether send marked err as Permanent, in which case
	// Do returns err without further attempts.
	permanent bool
	// unrecoverable is whether err is a transport error that cannot be
	// fixed by trying again. Do returns it unless ctx is done.
	unrecoverable bool
	// status is the status code of a retried response, or zero if
	// there was none.
	status int
	// retryAfter is the wait asked for by a retried response's
	// Retry-After header.
	retryAfter time.Duration
	// limited is the response if it was a 429.
	limited *http.Response
}

// classify reads the result of a call to send and decides whether it is
// a response to return, a failure to retry, or a failure that must not be
// retried. It reads and closes the body of resp.
func classify(resp *http.Response, err error) outcome {
	if err != nil {
		var perm permanentError
		if errors.As(err, &perm) {
			return outcome{err: perm.err, permanent: true}
		}
		return outcome{err: err, unrecoverable: isUnrecoverable(err)}
	}

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		o := outcome{
			err:        statusError(resp.Status, readExcerpt(resp)),
			status:     resp.StatusCode,
			retryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()),
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			o.limited = resp
		}
		return o
	}

	var body bytes.Buffer
	_, err = io.Copy(&body, resp.Body)
	resp.Body.Close()
	switch {
	case err != nil:
		return outcome{err: fmt.Errorf("%s: read body: %w", resp.Status, err), status: resp.StatusCode}
	case body.Len() == 0 && isSuccess(resp.StatusCode) && resp.StatusCode != http.StatusNoContent:
		return outcome{err: fmt.Errorf("%s: empty response body", resp.Status), status: resp.StatusCode}
	}
	return outcome{resp: &Response{Status: resp.Status, StatusCode: resp.StatusCode, Header: resp.Header, Body: body.Bytes()}}
}

// withContext returns err wrapped with ctx.Err(), unless it already wraps it.
func withContext(ctx context.Context, err error) error {
	if errors.Is(err, ctx.Err()) {
		return err
	}
	return fmt.Errorf("%w: %w", ctx.Err(), err)
}

// backoff returns the wait before the given retry attempt.
func backoff(attempt int, p Policy) time.Duration {
	shift := attempt - 1
	if shift >= 62 || p.BaseDelay > p.MaxDelay>>shift {
		return p.MaxDelay
	}
	return min(p.BaseDelay<<shift, p.MaxDelay)
}

// readExcerpt returns the start of resp's body, for an error message. It
// discards a bounded amount of the rest, so the connection can be reused,
// and closes the body.
func readExcerpt(resp *http.Response) []byte {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodyLimit))
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, drainLimit))
	resp.Body.Close()
	return body
}

const (
	// errorBodyLimit is how much of a retried response's body is kept for
	// the error message.
	errorBodyLimit = 256
	// drainLimit is how much more of a retried response's body is read
	// and discarded so the connection can be reused.
	drainLimit = 64 << 10
)

// paceDelay returns the wait after o, a 429 response: as long as its
// Retry-After header asks, or as pacer decides if the header is missing
// or gives no wait, up to maxPaceWait. It also returns which of the two
// set the wait, for logging. It reports false if neither gives a wait.
func paceDelay(pacer Pacer, o outcome) (d time.Duration, source string, ok bool) {
	if o.retryAfter > 0 {
		return min(o.retryAfter, maxPaceWait), "Retry-After", true
	}
	if pacer == nil {
		return 0, "", false
	}
	d, ok = pacer.Delay(o.limited)
	if !ok || d <= 0 {
		return 0, "", false
	}
	return min(d, maxPaceWait), "pacer", true
}

// maxPaceWait caps the wait after a 429 response. It is also the cap on
// other waits when Policy.MaxDelay is not set.
const maxPaceWait = 30 * time.Minute

// wait waits for d, or until ctx is done, in which case it returns
// ctx.Err().
func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// statusError returns an error for a retried response with the given
// status and the start of its body.
func statusError(status string, body []byte) error {
	if len(body) == 0 {
		return errors.New(status)
	}
	return fmt.Errorf("%s: %s", status, body)
}

// isUnrecoverable reports whether a transport error cannot be fixed by
// trying again: a certificate that does not verify, or a redirect loop.
func isUnrecoverable(err error) bool {
	var (
		verifyErr    *tls.CertificateVerificationError
		authorityErr x509.UnknownAuthorityError
		hostErr      x509.HostnameError
		invalidErr   x509.CertificateInvalidError
	)
	if errors.As(err, &verifyErr) || errors.As(err, &authorityErr) || errors.As(err, &hostErr) || errors.As(err, &invalidErr) {
		return true
	}
	// http.Client reports too many redirects with an untyped error.
	var urlErr *url.Error
	return errors.As(err, &urlErr) && strings.HasPrefix(urlErr.Err.Error(), "stopped after ")
}

// parseRetryAfter returns the wait requested by a Retry-After header
// value, which is either a number of seconds or an HTTP date. It returns
// zero if the value is empty, invalid or in the past.
func parseRetryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	secs, err := strconv.Atoi(v)
	if err == nil {
		const maxSecs = int(math.MaxInt64 / int64(time.Second))
		return time.Duration(min(max(secs, 0), maxSecs)) * time.Second
	}
	t, err := http.ParseTime(v)
	if err != nil {
		return 0
	}
	return max(t.Sub(now), 0)
}

func isSuccess(code int) bool {
	return 200 <= code && code < 300
}

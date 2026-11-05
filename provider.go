// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package entcollect

import (
	"context"
	"log/slog"
)

// Provider runs identity sync operations against a single identity
// source. Implementations are stateless between calls; all
// persistent state lives in the [Store].
//
// FullSync performs an exhaustive sync: enumerate all entities from
// the source, publish them, and detect deletions where applicable.
//
// IncrementalSync performs a partial sync: fetch only entities that
// changed since the last sync (using a cursor, delta link, or
// timestamp filter). If a provider has no meaningful incremental
// mode, IncrementalSync should behave identically to FullSync.
//
// The adapter calls these methods on its own schedule and is
// responsible for timing, retry, and the sync loop lifecycle.
//
// A nil error means the sync succeeded, and the adapter should commit
// the changes it made to the Store. An *IncompleteError means the sync
// finished and published what it could, but some data could not be
// collected: the adapter should commit the changes and report the error,
// for example as a degraded status. Data that could not be collected is
// fetched again no sooner than the next full sync. Any other error means
// the sync failed, and the adapter should discard the changes.
type Provider interface {
	FullSync(ctx context.Context, store Store, pub Publisher, log *slog.Logger) error
	IncrementalSync(ctx context.Context, store Store, pub Publisher, log *slog.Logger) error
}

// IncompleteError is returned by a sync that finished but could not
// collect some data, for example an optional enrichment that failed for
// some entities. The sync's changes to the Store are consistent and
// should be committed. Adapters detect it with errors.As, so a provider
// must not wrap an IncompleteError in the error for a failed sync.
type IncompleteError struct {
	// Err describes the data that could not be collected.
	Err error
}

func (e *IncompleteError) Error() string {
	if e.Err == nil {
		return "incomplete sync"
	}
	return "incomplete sync: " + e.Err.Error()
}

func (e *IncompleteError) Unwrap() error { return e.Err }

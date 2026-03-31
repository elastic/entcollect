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
type Provider interface {
	FullSync(ctx context.Context, store Store, pub Publisher, log *slog.Logger) error
	IncrementalSync(ctx context.Context, store Store, pub Publisher, log *slog.Logger) error
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package entcollect

import (
	"encoding/json"
	"fmt"
)

// Buffer satisfies [Store].
var _ Store = (*Buffer)(nil)

// Buffer wraps a [Store], holding writes in memory until [Buffer.Commit]
// is called. Reads see pending writes (read-your-writes semantics).
//
// The intended use is: the adapter creates a Buffer around its real
// store, passes it to a provider's sync method, and calls Commit
// after confirming that published events have been acknowledged.
// If the process crashes before Commit, the underlying store is
// unchanged and the next sync replays from the old position.
type Buffer struct {
	base    Store
	pending map[string]json.RawMessage
	deleted map[string]struct{}
}

// NewBuffer returns a Buffer that defers writes to base.
func NewBuffer(base Store) *Buffer {
	return &Buffer{
		base:    base,
		pending: make(map[string]json.RawMessage),
		deleted: make(map[string]struct{}),
	}
}

// Get decodes the value for key into dst. Pending writes are
// visible; pending deletes return [ErrKeyNotFound].
func (b *Buffer) Get(key string, dst any) error {
	if _, ok := b.deleted[key]; ok {
		return fmt.Errorf("buffer get %q: %w", key, ErrKeyNotFound)
	}
	raw, ok := b.pending[key]
	if ok {
		err := json.Unmarshal(raw, dst)
		if err != nil {
			return fmt.Errorf("buffer decode %q: %w", key, err)
		}
		return nil
	}
	return b.base.Get(key, dst)
}

// Set encodes value and holds it in the buffer.
func (b *Buffer) Set(key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("buffer encode %q: %w", key, err)
	}
	delete(b.deleted, key)
	b.pending[key] = raw
	return nil
}

// Delete marks key for removal. The delete is applied on Commit.
func (b *Buffer) Delete(key string) error {
	delete(b.pending, key)
	b.deleted[key] = struct{}{}
	return nil
}

// Each iterates all key-value pairs visible through the buffer:
// base keys not shadowed by a pending delete, plus pending writes.
// The decode function deserialises the value into the destination.
// Return false from fn to stop iteration.
func (b *Buffer) Each(fn func(key string, decode func(any) error) (bool, error)) error {
	seen := make(map[string]struct{})

	for key, raw := range b.pending {
		seen[key] = struct{}{}
		cont, err := fn(key, func(dst any) error {
			return json.Unmarshal(raw, dst)
		})
		if err != nil {
			return err
		}
		if !cont {
			return nil
		}
	}

	return b.base.Each(func(key string, decode func(any) error) (bool, error) {
		if _, ok := seen[key]; ok {
			return true, nil
		}
		if _, ok := b.deleted[key]; ok {
			return true, nil
		}
		return fn(key, decode)
	})
}

// Commit flushes all pending writes and deletes to the underlying
// store, then resets the buffer. If any write or delete fails,
// Commit stops and returns the error; the buffer is left in a
// partially-flushed state so the caller can inspect or retry.
func (b *Buffer) Commit() error {
	for key := range b.deleted {
		err := b.base.Delete(key)
		if err != nil {
			return fmt.Errorf("buffer commit delete %q: %w", key, err)
		}
	}
	for key, raw := range b.pending {
		err := b.base.Set(key, json.RawMessage(raw))
		if err != nil {
			return fmt.Errorf("buffer commit set %q: %w", key, err)
		}
	}
	b.pending = make(map[string]json.RawMessage)
	b.deleted = make(map[string]struct{})
	return nil
}

// Discard drops all pending writes and deletes without flushing
// to the underlying store.
func (b *Buffer) Discard() {
	b.pending = make(map[string]json.RawMessage)
	b.deleted = make(map[string]struct{})
}


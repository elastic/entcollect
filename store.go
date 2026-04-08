// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package entcollect

import "errors"

// ErrKeyNotFound is returned by [Store].Get when the requested key
// does not exist. Callers should use [errors.Is] to check for it.
var ErrKeyNotFound = errors.New("key not found")

// Registry provides access to named [Store] instances. Runtime
// adapters implement this to bridge their storage backend to the
// shared library. The Beats adapter does not use Registry (it
// opens stores through its own kvstore layer); the OTel receiver
// resolves a storage extension and type-asserts it to Registry.
//
// Implementations are responsible for the lifecycle of returned
// stores. Registry does not define a Close method; the adapter's
// runtime (e.g. OTel extension shutdown) handles cleanup.
type Registry interface {
	Store(name string) (Store, error)
}

// Store is a key-value store for provider state. The shared library
// reads and writes state through this interface; adapter layers
// supply implementations backed by their runtime's storage (bbolt
// for Beats, Elasticsearch for OTel).
//
// Implementations must be safe for sequential use from a single
// goroutine. Thread safety across goroutines is not required;
// providers run sync operations sequentially.
type Store interface {
	// Get decodes the value for key into dst, which must be a
	// pointer. Returns [ErrKeyNotFound] if the key does not exist.
	Get(key string, dst any) error

	// Set encodes value and stores it under key.
	Set(key string, value any) error

	// Delete removes the key. It is not an error if the key is
	// absent.
	Delete(key string) error

	// Each iterates all key-value pairs. The decode function
	// deserialises the stored bytes into the destination, which
	// must be a pointer. Return false from fn to stop iteration.
	Each(fn func(key string, decode func(any) error) (bool, error)) error
}

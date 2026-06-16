// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package scratch provides temporary file-backed storage for enrichment
// computation during sync cycles. A DB is created at the start of a sync
// and deleted when done, keeping heap usage proportional to page size
// rather than total directory size.
package scratch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	bolt "go.etcd.io/bbolt"
)

const filePrefix = "entcollect-scratch-"

// DB is a temporary bbolt database for enrichment computation.
// It provides adjacency-graph primitives for writing edges during
// API fetch and reading them during document enrichment.
type DB struct {
	db   *bolt.DB
	path string
}

// Open creates a new temporary bbolt database in dir. If dir is
// empty, os.TempDir() is used. The caller must call Close to remove
// the temporary file.
func Open(dir string) (*DB, error) {
	if dir == "" {
		dir = os.TempDir()
	}
	f, err := os.CreateTemp(dir, filePrefix+"*.db")
	if err != nil {
		return nil, fmt.Errorf("scratch: create temp file: %w", err)
	}
	path := f.Name()
	if err := f.Close(); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("scratch: close temp file: %w", err)
	}

	db, err := bolt.Open(path, 0o600, &bolt.Options{
		NoSync:         true,
		NoFreelistSync: true,
	})
	if err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("scratch: open bbolt: %w", err)
	}
	return &DB{db: db, path: path}, nil
}

// Path returns the filesystem path of the scratch database.
func (d *DB) Path() string { return d.path }

// Size returns the current file size in bytes.
func (d *DB) Size() int64 {
	info, err := os.Stat(d.path)
	if err != nil {
		return 0
	}
	return info.Size()
}

// PutJSON stores a JSON-encoded value under key in bucket. The bucket
// is created if it does not exist.
func (d *DB) PutJSON(bucket, key string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("scratch: marshal %s/%s: %w", bucket, key, err)
	}
	return d.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}
		return b.Put([]byte(key), data)
	})
}

// GetJSON retrieves a JSON-encoded value from bucket/key into dst.
// Returns false if the bucket or key does not exist.
func (d *DB) GetJSON(bucket, key string, dst any) (bool, error) {
	var data []byte
	err := d.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		v := b.Get([]byte(key))
		if v != nil {
			data = make([]byte, len(v))
			copy(data, v)
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	if data == nil {
		return false, nil
	}
	return true, json.Unmarshal(data, dst)
}

// Link adds a directed edge from → to in the named bucket. Edges are
// stored as composite keys ("from\x00to") in a single flat bucket.
// Multiple edges from the same source accumulate — each call writes one
// key without reading existing edges (no read-modify-write).
func (d *DB) Link(bucket, from, to string) error {
	return d.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}
		return b.Put(edgeKey(from, to), nil)
	})
}

// Neighbors returns all destination IDs linked from source in the
// named bucket. Returns nil (not an error) if the source has no edges.
// Results are returned in ascending byte order of the destination ID.
func (d *DB) Neighbors(bucket, from string) ([]string, error) {
	var result []string
	prefix := edgePrefix(from)
	err := d.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			result = append(result, string(k[len(prefix):]))
		}
		return nil
	})
	return result, err
}

// BatchLink adds multiple edges from the same source in a single
// transaction.
func (d *DB) BatchLink(bucket, from string, targets []string) error {
	if len(targets) == 0 {
		return nil
	}
	return d.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucket))
		if err != nil {
			return err
		}
		for _, to := range targets {
			if err := b.Put(edgeKey(from, to), nil); err != nil {
				return err
			}
		}
		return nil
	})
}

// Tx exposes write operations within a BatchWrite transaction. It does
// not own the transaction — the enclosing BatchWrite commits or rolls
// back based on the error returned from the callback.
type Tx struct {
	tx *bolt.Tx
}

// PutJSON stores a JSON-encoded value within the enclosing transaction.
func (t *Tx) PutJSON(bucket, key string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("scratch: marshal %s/%s: %w", bucket, key, err)
	}
	b, err := t.tx.CreateBucketIfNotExists([]byte(bucket))
	if err != nil {
		return err
	}
	return b.Put([]byte(key), data)
}

// Link adds a directed edge within the enclosing transaction.
func (t *Tx) Link(bucket, from, to string) error {
	b, err := t.tx.CreateBucketIfNotExists([]byte(bucket))
	if err != nil {
		return err
	}
	return b.Put(edgeKey(from, to), nil)
}

// BatchLink adds multiple edges from the same source within the
// enclosing transaction.
func (t *Tx) BatchLink(bucket, from string, targets []string) error {
	if len(targets) == 0 {
		return nil
	}
	b, err := t.tx.CreateBucketIfNotExists([]byte(bucket))
	if err != nil {
		return err
	}
	for _, to := range targets {
		if err := b.Put(edgeKey(from, to), nil); err != nil {
			return err
		}
	}
	return nil
}

// BatchWrite groups multiple write operations into a single bbolt
// transaction. The transaction commits if fn returns nil, or rolls
// back otherwise.
func (d *DB) BatchWrite(fn func(tx *Tx) error) error {
	return d.db.Update(func(btx *bolt.Tx) error {
		return fn(&Tx{tx: btx})
	})
}

// Close closes the database and removes the temporary file. It is
// safe to call on a nil *DB.
func (d *DB) Close() error {
	if d == nil || d.db == nil {
		return nil
	}
	closeErr := d.db.Close()
	removeErr := os.Remove(d.path)
	d.db = nil
	return errors.Join(closeErr, removeErr)
}

// edgeSep separates source and destination IDs in a composite edge key
// (from<sep>to). The NUL byte does not occur in provider entity IDs
// (EntraID GUIDs and Okta IDs are printable ASCII), so it is an
// unambiguous delimiter and sorts below every real ID byte.
const edgeSep = "\x00"

// edgeKey builds the composite key "from\x00to" for a directed edge.
// Edges are stored as keys in a single flat bucket rather than as
// entries in a per-source sub-bucket, which avoids one B+tree (and its
// page overhead) per source node.
func edgeKey(from, to string) []byte {
	return []byte(from + edgeSep + to)
}

// edgePrefix builds the scan prefix "from\x00" used to enumerate every
// edge originating at from via a cursor seek.
func edgePrefix(from string) []byte {
	return []byte(from + edgeSep)
}

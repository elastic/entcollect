// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package entcollect

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"testing"
)

func TestBufferReadYourWrites(t *testing.T) {
	base := newMemStore()
	buf := NewBuffer(base)

	if err := buf.Set("k1", "hello"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	var got string
	if err := buf.Get("k1", &got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "hello" {
		t.Errorf("Get(k1) = %q; want %q", got, "hello")
	}

	// Base should be untouched.
	if err := base.Get("k1", &got); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("base.Get(k1) err = %v; want ErrKeyNotFound", err)
	}
}

func TestBufferReadThrough(t *testing.T) {
	base := newMemStore()
	if err := base.Set("existing", 42); err != nil {
		t.Fatal(err)
	}

	buf := NewBuffer(base)

	var got int
	if err := buf.Get("existing", &got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != 42 {
		t.Errorf("Get(existing) = %d; want 42", got)
	}
}

func TestBufferDeleteHidesPending(t *testing.T) {
	base := newMemStore()
	buf := NewBuffer(base)

	if err := buf.Set("k", "value"); err != nil {
		t.Fatal(err)
	}
	if err := buf.Delete("k"); err != nil {
		t.Fatal(err)
	}

	var got string
	if err := buf.Get("k", &got); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Get(k) after delete err = %v; want ErrKeyNotFound", err)
	}
}

func TestBufferDeleteHidesBase(t *testing.T) {
	base := newMemStore()
	if err := base.Set("k", "base-value"); err != nil {
		t.Fatal(err)
	}

	buf := NewBuffer(base)
	if err := buf.Delete("k"); err != nil {
		t.Fatal(err)
	}

	var got string
	if err := buf.Get("k", &got); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Get(k) after delete err = %v; want ErrKeyNotFound", err)
	}
}

func TestBufferCommit(t *testing.T) {
	base := newMemStore()
	buf := NewBuffer(base)

	if err := buf.Set("a", "alpha"); err != nil {
		t.Fatal(err)
	}
	if err := buf.Set("b", "beta"); err != nil {
		t.Fatal(err)
	}
	if err := buf.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	var got string
	if err := base.Get("a", &got); err != nil {
		t.Fatalf("base.Get(a): %v", err)
	}
	if got != "alpha" {
		t.Errorf("base.Get(a) = %q; want %q", got, "alpha")
	}
	if err := base.Get("b", &got); err != nil {
		t.Fatalf("base.Get(b): %v", err)
	}
	if got != "beta" {
		t.Errorf("base.Get(b) = %q; want %q", got, "beta")
	}
}

func TestBufferCommitDelete(t *testing.T) {
	base := newMemStore()
	if err := base.Set("k", "old"); err != nil {
		t.Fatal(err)
	}

	buf := NewBuffer(base)
	if err := buf.Delete("k"); err != nil {
		t.Fatal(err)
	}
	if err := buf.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	var got string
	if err := base.Get("k", &got); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("base.Get(k) after commit err = %v; want ErrKeyNotFound", err)
	}
}

func TestBufferDiscard(t *testing.T) {
	base := newMemStore()
	buf := NewBuffer(base)

	if err := buf.Set("k", "value"); err != nil {
		t.Fatal(err)
	}
	buf.Discard()

	var got string
	if err := buf.Get("k", &got); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Get(k) after discard err = %v; want ErrKeyNotFound", err)
	}
}

func TestBufferEach(t *testing.T) {
	base := newMemStore()
	if err := base.Set("base1", "b1"); err != nil {
		t.Fatal(err)
	}
	if err := base.Set("base2", "b2"); err != nil {
		t.Fatal(err)
	}

	buf := NewBuffer(base)
	if err := buf.Set("new1", "n1"); err != nil {
		t.Fatal(err)
	}
	if err := buf.Set("base1", "overwritten"); err != nil {
		t.Fatal(err)
	}
	if err := buf.Delete("base2"); err != nil {
		t.Fatal(err)
	}

	var keys []string
	vals := make(map[string]string)
	err := buf.Each(func(key string, decode func(any) error) (bool, error) {
		var v string
		if err := decode(&v); err != nil {
			return false, err
		}
		keys = append(keys, key)
		vals[key] = v
		return true, nil
	})
	if err != nil {
		t.Fatalf("Each: %v", err)
	}

	sort.Strings(keys)
	if len(keys) != 2 {
		t.Fatalf("Each yielded %d keys; want 2: %v", len(keys), keys)
	}
	if keys[0] != "base1" || keys[1] != "new1" {
		t.Errorf("Each keys = %v; want [base1 new1]", keys)
	}
	if vals["base1"] != "overwritten" {
		t.Errorf("base1 = %q; want %q", vals["base1"], "overwritten")
	}
	if vals["new1"] != "n1" {
		t.Errorf("new1 = %q; want %q", vals["new1"], "n1")
	}
}

func TestBufferEachStopEarly(t *testing.T) {
	base := newMemStore()
	buf := NewBuffer(base)

	for i := range 5 {
		if err := buf.Set(fmt.Sprintf("k%d", i), i); err != nil {
			t.Fatal(err)
		}
	}

	var count int
	err := buf.Each(func(_ string, _ func(any) error) (bool, error) {
		count++
		return false, nil
	})
	if err != nil {
		t.Fatalf("Each: %v", err)
	}
	if count != 1 {
		t.Errorf("Each called fn %d times; want 1", count)
	}
}

func TestBufferSetAfterDelete(t *testing.T) {
	base := newMemStore()
	buf := NewBuffer(base)

	if err := buf.Set("k", "first"); err != nil {
		t.Fatal(err)
	}
	if err := buf.Delete("k"); err != nil {
		t.Fatal(err)
	}
	if err := buf.Set("k", "second"); err != nil {
		t.Fatal(err)
	}

	var got string
	if err := buf.Get("k", &got); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "second" {
		t.Errorf("Get(k) = %q; want %q", got, "second")
	}
}

// memStore is a minimal in-memory Store for testing.
type memStore struct {
	data map[string]json.RawMessage
}

func newMemStore() *memStore {
	return &memStore{data: make(map[string]json.RawMessage)}
}

func (m *memStore) Get(key string, dst any) error {
	raw, ok := m.data[key]
	if !ok {
		return fmt.Errorf("memstore get %q: %w", key, ErrKeyNotFound)
	}
	return json.Unmarshal(raw, dst)
}

func (m *memStore) Set(key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	m.data[key] = raw
	return nil
}

func (m *memStore) Delete(key string) error {
	delete(m.data, key)
	return nil
}

func (m *memStore) Each(fn func(string, func(any) error) (bool, error)) error {
	for key, raw := range m.data {
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
	return nil
}

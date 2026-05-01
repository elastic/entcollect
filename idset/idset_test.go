// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package idset

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/elastic/entcollect"
)

func TestEmptyFirstRun(t *testing.T) {
	store := newTestStore()
	s := New(4)

	if err := s.Load(store); err != nil {
		t.Fatalf("Load: %v", err)
	}

	s.Add("a")
	s.Add("b")

	missing := s.Missing()
	if len(missing) != 0 {
		t.Errorf("Missing() = %v; want empty (first run)", missing)
	}

	if err := s.Save(store); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Verify data was persisted.
	var m meta
	if err := store.Get(metaKey, &m); err != nil {
		t.Fatalf("Get meta: %v", err)
	}
	if m.Shards != 4 {
		t.Errorf("meta.Shards = %d; want 4", m.Shards)
	}
}

func TestDetectMissing(t *testing.T) {
	store := newTestStore()

	// Simulate a previous sync with IDs a, b, c.
	s1 := New(4)
	if err := s1.Load(store); err != nil {
		t.Fatal(err)
	}
	s1.Add("a")
	s1.Add("b")
	s1.Add("c")
	if err := s1.Save(store); err != nil {
		t.Fatal(err)
	}

	// New sync: a and c present, b missing.
	s2 := New(4)
	if err := s2.Load(store); err != nil {
		t.Fatal(err)
	}
	s2.Add("a")
	s2.Add("c")

	missing := s2.Missing()
	if len(missing) != 1 || missing[0] != "b" {
		t.Errorf("Missing() = %v; want [b]", missing)
	}
}

func TestDetectMultipleMissing(t *testing.T) {
	store := newTestStore()

	s1 := New(4)
	if err := s1.Load(store); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		s1.Add(id)
	}
	if err := s1.Save(store); err != nil {
		t.Fatal(err)
	}

	s2 := New(4)
	if err := s2.Load(store); err != nil {
		t.Fatal(err)
	}
	s2.Add("a")
	s2.Add("d")

	missing := s2.Missing()
	want := []string{"b", "c", "e"}
	if len(missing) != len(want) {
		t.Fatalf("Missing() = %v; want %v", missing, want)
	}
	for i := range want {
		if missing[i] != want[i] {
			t.Errorf("Missing()[%d] = %q; want %q", i, missing[i], want[i])
		}
	}
}

func TestNoMissing(t *testing.T) {
	store := newTestStore()

	s1 := New(4)
	if err := s1.Load(store); err != nil {
		t.Fatal(err)
	}
	s1.Add("a")
	s1.Add("b")
	if err := s1.Save(store); err != nil {
		t.Fatal(err)
	}

	s2 := New(4)
	if err := s2.Load(store); err != nil {
		t.Fatal(err)
	}
	s2.Add("a")
	s2.Add("b")
	s2.Add("c")

	missing := s2.Missing()
	if len(missing) != 0 {
		t.Errorf("Missing() = %v; want empty", missing)
	}
}

func TestRehashOnShardCountChange(t *testing.T) {
	store := newTestStore()

	// Save with 4 shards.
	s1 := New(4)
	if err := s1.Load(store); err != nil {
		t.Fatal(err)
	}
	ids := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	for _, id := range ids {
		s1.Add(id)
	}
	if err := s1.Save(store); err != nil {
		t.Fatal(err)
	}

	// Load with 8 shards; should rehash transparently.
	s2 := New(8)
	if err := s2.Load(store); err != nil {
		t.Fatal(err)
	}

	// All original IDs should be present, so adding them all and
	// checking Missing() returns empty confirms rehash correctness.
	for _, id := range ids {
		s2.Add(id)
	}
	missing := s2.Missing()
	if len(missing) != 0 {
		t.Errorf("Missing() after rehash = %v; want empty", missing)
	}

	// Remove one and confirm detection still works after rehash.
	s3 := New(8)
	if err := s3.Load(store); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if id != "gamma" {
			s3.Add(id)
		}
	}
	missing = s3.Missing()
	if len(missing) != 1 || missing[0] != "gamma" {
		t.Errorf("Missing() after rehash = %v; want [gamma]", missing)
	}
	if err := s3.Save(store); err != nil {
		t.Fatal(err)
	}

	// Load with 2 shards (reduction); should also rehash transparently.
	s4 := New(2)
	if err := s4.Load(store); err != nil {
		t.Fatal(err)
	}
	remaining := []string{"alpha", "beta", "delta", "epsilon"}
	for _, id := range remaining {
		s4.Add(id)
	}
	missing = s4.Missing()
	if len(missing) != 0 {
		t.Errorf("Missing() after shard reduction = %v; want empty", missing)
	}

	// Drop one more to confirm deletion detection after reduction.
	s5 := New(2)
	if err := s5.Load(store); err != nil {
		t.Fatal(err)
	}
	for _, id := range remaining {
		if id != "delta" {
			s5.Add(id)
		}
	}
	missing = s5.Missing()
	if len(missing) != 1 || missing[0] != "delta" {
		t.Errorf("Missing() after shard reduction = %v; want [delta]", missing)
	}
}

func TestDirtyTrackingMinimalWrites(t *testing.T) {
	store := newTestStore()

	// First sync: add a, b.
	s1 := New(4)
	if err := s1.Load(store); err != nil {
		t.Fatal(err)
	}
	s1.Add("a")
	s1.Add("b")
	if err := s1.Save(store); err != nil {
		t.Fatal(err)
	}

	// Second sync: same IDs, no changes.
	s2 := New(4)
	if err := s2.Load(store); err != nil {
		t.Fatal(err)
	}
	s2.Add("a")
	s2.Add("b")

	// Wrap store to count Set calls.
	var setCalls int
	wrapper := &countingStore{testStore: store, setCalls: &setCalls}
	if err := s2.Save(wrapper); err != nil {
		t.Fatal(err)
	}

	// Only meta should be written; no shard writes since nothing changed.
	if setCalls != 1 {
		t.Errorf("Save wrote %d keys; want 1 (meta only)", setCalls)
	}
}

type countingStore struct {
	*testStore
	setCalls *int
}

func (c *countingStore) Set(key string, value any) error {
	*c.setCalls++
	return c.testStore.Set(key, value)
}

func TestSaveCleansEmptyShards(t *testing.T) {
	store := newTestStore()

	// First sync: add IDs.
	s1 := New(4)
	if err := s1.Load(store); err != nil {
		t.Fatal(err)
	}
	s1.Add("x")
	if err := s1.Save(store); err != nil {
		t.Fatal(err)
	}

	// Second sync: no IDs at all, so x is missing.
	s2 := New(4)
	if err := s2.Load(store); err != nil {
		t.Fatal(err)
	}

	missing := s2.Missing()
	if len(missing) != 1 || missing[0] != "x" {
		t.Errorf("Missing() = %v; want [x]", missing)
	}

	if err := s2.Save(store); err != nil {
		t.Fatal(err)
	}

	// The shard that held x should be deleted.
	idx := shard("x", 4)
	key := shardKey(idx)
	var ids []string
	err := store.Get(key, &ids)
	if err == nil {
		t.Errorf("shard %d still exists with %v after all entities removed", idx, ids)
	}
}

func TestWasPresent(t *testing.T) {
	store := newTestStore()

	s1 := New(4)
	if err := s1.Load(store); err != nil {
		t.Fatal(err)
	}
	s1.Add("a")
	s1.Add("b")
	if err := s1.Save(store); err != nil {
		t.Fatal(err)
	}

	// Second sync: load previous state.
	s2 := New(4)
	if err := s2.Load(store); err != nil {
		t.Fatal(err)
	}

	// WasPresent reports prev-set membership before and after Add.
	if !s2.WasPresent("a") {
		t.Errorf("WasPresent(a) = false before Add; want true")
	}
	if s2.WasPresent("c") {
		t.Errorf("WasPresent(c) = true before Add; want false (never seen)")
	}

	s2.Add("a")
	s2.Add("c")

	// Add must not change prev-set membership.
	if !s2.WasPresent("a") {
		t.Errorf("WasPresent(a) = false after Add; want true")
	}
	if s2.WasPresent("c") {
		t.Errorf("WasPresent(c) = true after Add; want false (not in prev)")
	}

	// b was not Added this sync, so it should be Missing and not WasPresent after re-load.
	if err := s2.Save(store); err != nil {
		t.Fatal(err)
	}

	s3 := New(4)
	if err := s3.Load(store); err != nil {
		t.Fatal(err)
	}
	if s3.WasPresent("b") {
		t.Errorf("WasPresent(b) = true in s3; want false (b was removed in s2)")
	}
	if !s3.WasPresent("c") {
		t.Errorf("WasPresent(c) = false in s3; want true (c was added in s2)")
	}
}

// testStore is a minimal in-memory entcollect.Store for testing.
type testStore struct {
	data map[string]json.RawMessage
}

func newTestStore() *testStore {
	return &testStore{data: make(map[string]json.RawMessage)}
}

func (s *testStore) Get(key string, dst any) error {
	raw, ok := s.data[key]
	if !ok {
		return fmt.Errorf("teststore get %q: %w", key, entcollect.ErrKeyNotFound)
	}
	return json.Unmarshal(raw, dst)
}

func (s *testStore) Set(key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	s.data[key] = raw
	return nil
}

func (s *testStore) Delete(key string) error {
	delete(s.data, key)
	return nil
}

func (s *testStore) Each(fn func(string, func(any) error) (bool, error)) error {
	for key, raw := range s.data {
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

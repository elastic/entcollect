// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package idset

import (
	"encoding/json"
	"fmt"
	"strconv"
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
	if err := store.Get("idset.meta", &m); err != nil {
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
	key := "idset.shard." + strconv.Itoa(idx)
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

// TestPartialShardCorruption verifies idset behavior when some shard
// keys are missing from the store (meta is intact but shard data is
// gone). This simulates partial store corruption.
//
// Four properties are asserted:
//
//  1. No spurious deletions: entities returned by the API whose IDs
//     happen to reside in surviving shards are not falsely reported
//     as missing.
//  2. False rediscovery: entities returned by the API whose IDs
//     reside in deleted shards are not recognized as previously
//     present (WasPresent returns false). Providers use WasPresent
//     to choose between discovered and modified actions, so these
//     entities get a one-time false "discovered" instead of
//     "modified." The entity data is unaffected; only the action
//     label is inaccurate for the corrupted sync cycle. After Save
//     repairs the shards, subsequent syncs correctly report
//     "modified."
//  3. Missed deletions: entities that were removed from the API AND
//     whose IDs resided only in deleted shards are silently lost —
//     they produce no deletion event because their IDs are absent
//     from prev (the shard was not loaded) and therefore cannot
//     appear in Missing(). This is a known limitation of partial
//     corruption.
//  4. Shards rewritten: after a full sync cycle (Add all current
//     API entities, then Save), all shards are repopulated from the
//     current set, repairing the corruption for subsequent syncs.
func TestPartialShardCorruption(t *testing.T) {
	store := newTestStore()

	// Sync 1: healthy state
	// IDs are chosen so that FNV-1a distributes them across all 4 shards:
	//   shard 0: a, e    shard 1: b, f
	//   shard 2: c, g    shard 3: d, h
	s1 := New(4)
	if err := s1.Load(store); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		s1.Add(id)
	}
	if err := s1.Save(store); err != nil {
		t.Fatal(err)
	}

	// Corrupt store: delete shards 2 and 3
	// Meta still says 4 shards, but shard 2 (c, g) and shard 3
	// (d, h) are gone.
	store.Delete("idset.shard.2")
	store.Delete("idset.shard.3")

	// Sync 2: mixed scenario
	// API returns a, b, c, e, f — c is still in the API but its
	// shard (2) was deleted. d, g, h are removed from the API AND
	// their shards are gone.
	s2 := New(4)
	if err := s2.Load(store); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c", "e", "f"} {
		s2.Add(id)
	}

	// Property 1: no spurious deletions.
	// a, b, e, f are in curr and in surviving prev shards. They
	// must not appear in Missing().
	missing := s2.Missing()
	for _, id := range []string{"a", "b", "e", "f"} {
		for _, m := range missing {
			if m == id {
				t.Errorf("spurious deletion: %q is in Missing() but was returned by API", id)
			}
		}
	}

	// Entities in surviving shards are correctly recognized.
	for _, id := range []string{"a", "b", "e", "f"} {
		if !s2.WasPresent(id) {
			t.Errorf("WasPresent(%q) = false; want true (shard survived corruption)", id)
		}
	}

	// Property 2: false rediscovery.
	// c is still returned by the API, but shard 2 was deleted from
	// the store. Since c's ID was not loaded into prev, WasPresent
	// returns false. A provider using WasPresent to select between
	// ActionDiscovered and ActionModified would emit a false
	// "discovered" for c during this sync cycle.
	if s2.WasPresent("c") {
		t.Error("WasPresent(\"c\") = true; want false (shard 2 was deleted from store)")
	}

	// Property 3: missed deletions.
	// d, g, h were removed from the API, and their shards were
	// deleted from the store. Since their IDs are not in prev, they
	// cannot appear in Missing(). This is silent loss of deletion
	// detection — a known limitation.
	for _, id := range []string{"d", "g", "h"} {
		for _, m := range missing {
			if m == id {
				t.Errorf("unexpected: %q appeared in Missing() despite its shard being deleted from the store", id)
			}
		}
	}

	// c was re-added (still in API) so it must not appear as missing
	// either — its absence from prev means it cannot be in the
	// prev-minus-curr set that Missing() computes.
	if len(missing) != 0 {
		t.Errorf("Missing() = %v; want empty (surviving entities re-added, deleted-shard entities invisible)", missing)
	}

	// Save repairs the idset
	if err := s2.Save(store); err != nil {
		t.Fatal(err)
	}

	// Property 4: all shards rewritten from current API entities.
	// After Save, the store should have the meta key plus shard keys
	// for shards that contain at least one current ID. Shards 0 and
	// 1 have a,e and b,f respectively. Shard 2 now has c (g was
	// removed). Shard 3 is empty (d and h were removed) and should
	// be deleted rather than written as an empty slice.
	var m meta
	if err := store.Get("idset.meta", &m); err != nil {
		t.Fatalf("meta missing after Save: %v", err)
	}
	if m.Shards != 4 {
		t.Errorf("meta.Shards = %d; want 4", m.Shards)
	}

	for _, si := range []int{0, 1, 2} {
		var ids []string
		key := "idset.shard." + strconv.Itoa(si)
		if err := store.Get(key, &ids); err != nil {
			t.Errorf("shard %d missing after Save: %v", si, err)
		}
		if len(ids) == 0 {
			t.Errorf("shard %d empty after Save; expected populated", si)
		}
	}
	{
		var ids []string
		key := "idset.shard.3"
		err := store.Get(key, &ids)
		if err == nil {
			t.Errorf("shard 3 still exists after Save with ids=%v; want deleted (no current entities)", ids)
		}
	}

	// Sync 3: verify subsequent deletion detection works and
	// false rediscovery is repaired.
	s3 := New(4)
	if err := s3.Load(store); err != nil {
		t.Fatal(err)
	}
	// Remove "b" (shard 1) — should be detected since shard 1
	// was repaired. Keep "c" — it should now be recognized as
	// previously present (shard 2 was repaired by Save).
	for _, id := range []string{"a", "c", "e", "f"} {
		s3.Add(id)
	}

	// c is now correctly recognized after repair.
	if !s3.WasPresent("c") {
		t.Error("WasPresent(\"c\") = false after repair; want true (shard 2 was repaired by Save)")
	}

	missing = s3.Missing()
	if len(missing) != 1 || missing[0] != "b" {
		t.Errorf("Missing() after repair = %v; want [b]", missing)
	}
}

func TestPrefixIsolation(t *testing.T) {
	store := newTestStore()

	// Two prefixed sets sharing the same store.
	users := New(4, WithPrefix("users."))
	devices := New(4, WithPrefix("devices."))

	if err := users.Load(store); err != nil {
		t.Fatal(err)
	}
	if err := devices.Load(store); err != nil {
		t.Fatal(err)
	}

	users.Add("alice")
	users.Add("bob")
	devices.Add("host-1")

	if err := users.Save(store); err != nil {
		t.Fatal(err)
	}
	if err := devices.Save(store); err != nil {
		t.Fatal(err)
	}

	// Reload and verify isolation: removing alice from users should
	// not affect devices, and vice versa.
	users2 := New(4, WithPrefix("users."))
	devices2 := New(4, WithPrefix("devices."))

	if err := users2.Load(store); err != nil {
		t.Fatal(err)
	}
	if err := devices2.Load(store); err != nil {
		t.Fatal(err)
	}

	users2.Add("bob") // alice gone
	devices2.Add("host-1")

	missingUsers := users2.Missing()
	if len(missingUsers) != 1 || missingUsers[0] != "alice" {
		t.Errorf("users Missing() = %v; want [alice]", missingUsers)
	}

	missingDevices := devices2.Missing()
	if len(missingDevices) != 0 {
		t.Errorf("devices Missing() = %v; want empty", missingDevices)
	}
}

func TestPrefixDefaultEmpty(t *testing.T) {
	store := newTestStore()

	// Unprefixed set should use bare keys (backward compatible).
	s := New(4)
	if err := s.Load(store); err != nil {
		t.Fatal(err)
	}
	s.Add("x")
	if err := s.Save(store); err != nil {
		t.Fatal(err)
	}

	// Verify the meta key is the bare "idset.meta".
	var m meta
	if err := store.Get("idset.meta", &m); err != nil {
		t.Fatalf("bare meta key not found: %v", err)
	}
	if m.Shards != 4 {
		t.Errorf("meta.Shards = %d; want 4", m.Shards)
	}

	// Prefixed set should NOT see the bare keys.
	prefixed := New(4, WithPrefix("other."))
	if err := prefixed.Load(store); err != nil {
		t.Fatal(err)
	}
	prefixed.Add("y")

	// "x" should not appear as missing because prefixed never saw it.
	missing := prefixed.Missing()
	if len(missing) != 0 {
		t.Errorf("prefixed Missing() = %v; want empty (should not see bare keys)", missing)
	}
}

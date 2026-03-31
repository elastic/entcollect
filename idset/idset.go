// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package idset provides a sharded string-ID set backed by an
// [entcollect.Store], used for deletion detection during full sync.
//
// Typical usage:
//
//	s := idset.New(256)
//	s.Load(store)            // read previous sync's ID set
//	for _, entity := range fetched {
//	    s.Add(entity.ID)     // mark every entity seen this sync
//	}
//	gone := s.Missing()      // IDs present before but not now
//	s.Save(store)            // persist updated shards
package idset

import (
	"errors"
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"

	"github.com/elastic/entcollect"
)

const metaKey = "idset.meta"

// meta is the persisted metadata for a Set.
type meta struct {
	Shards int `json:"shards"`
}

// Set is a sharded ID set for deletion detection. It tracks which
// entity IDs were present in the previous sync (loaded from the
// store) and which IDs have been observed in the current sync
// (added via [Set.Add]). After the current sync completes,
// [Set.Missing] returns IDs that were present before but not added
// this time; these are candidates for deletion events.
type Set struct {
	shards int

	// prev holds the ID sets loaded from the store (previous sync).
	prev []map[string]struct{}

	// curr holds the ID sets built during the current sync.
	curr []map[string]struct{}

	// dirty tracks which shards have changed and need saving.
	dirty []bool
}

// New returns a Set that distributes IDs across n shards.
// The shard count must be at least 1.
func New(n int) *Set {
	if n < 1 {
		n = 1
	}
	return &Set{
		shards: n,
		prev:   make([]map[string]struct{}, n),
		curr:   make([]map[string]struct{}, n),
		dirty:  make([]bool, n),
	}
}

// Load reads the previous sync's shard data from the store. If the
// store has no ID set data yet (first run), Load is a no-op. If the
// stored shard count differs from the Set's configured count, Load
// re-hashes all IDs into the new shard layout.
func (s *Set) Load(store entcollect.Store) error {
	var m meta
	err := store.Get(metaKey, &m)
	if errors.Is(err, entcollect.ErrKeyNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("idset load meta: %w", err)
	}

	if m.Shards == s.shards {
		return s.loadDirect(store, m.Shards)
	}
	return s.loadRehash(store, m.Shards)
}

func shardKey(i int) string {
	return "idset.shard." + strconv.Itoa(i)
}

func shard(id string, n int) int {
	h := fnv.New32a()
	h.Write([]byte(id))
	return int(h.Sum32() % uint32(n))
}

func (s *Set) loadDirect(store entcollect.Store, n int) error {
	for i := range n {
		var ids []string
		err := store.Get(shardKey(i), &ids)
		if errors.Is(err, entcollect.ErrKeyNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("idset load shard %d: %w", i, err)
		}
		m := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			m[id] = struct{}{}
		}
		s.prev[i] = m
	}
	return nil
}

func (s *Set) loadRehash(store entcollect.Store, oldCount int) error {
	for i := range oldCount {
		var ids []string
		err := store.Get(shardKey(i), &ids)
		if errors.Is(err, entcollect.ErrKeyNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("idset load shard %d (rehash): %w", i, err)
		}
		for _, id := range ids {
			idx := shard(id, s.shards)
			if s.prev[idx] == nil {
				s.prev[idx] = make(map[string]struct{})
			}
			s.prev[idx][id] = struct{}{}
		}
	}
	// All shards are dirty after rehash since the layout changed.
	for i := range s.dirty {
		s.dirty[i] = true
	}
	return nil
}

// Add marks id as present in the current sync.
func (s *Set) Add(id string) {
	idx := shard(id, s.shards)
	if s.curr[idx] == nil {
		s.curr[idx] = make(map[string]struct{})
	}
	s.curr[idx][id] = struct{}{}

	if _, inPrev := s.prev[idx][id]; !inPrev {
		s.dirty[idx] = true
	}
}

// Missing returns IDs that were in the loaded (previous sync) set
// but were not Add-ed during the current sync. The returned slice
// is sorted for deterministic output.
func (s *Set) Missing() []string {
	var missing []string
	for i, prev := range s.prev {
		if prev == nil {
			continue
		}
		curr := s.curr[i]
		for id := range prev {
			if curr == nil || !contains(curr, id) {
				missing = append(missing, id)
			}
		}
	}
	sort.Strings(missing)
	return missing
}

func contains(m map[string]struct{}, key string) bool {
	_, ok := m[key]
	return ok
}

// Save writes changed shards and metadata to the store. Only shards
// that differ from the loaded state are written. Shards where
// previous IDs were not re-added (missing entities) are also marked
// dirty.
func (s *Set) Save(store entcollect.Store) error {
	// Mark shards dirty where entities disappeared.
	for i, prev := range s.prev {
		if prev == nil {
			continue
		}
		curr := s.curr[i]
		for id := range prev {
			if curr == nil || !contains(curr, id) {
				s.dirty[i] = true
				break
			}
		}
	}

	err := store.Set(metaKey, meta{Shards: s.shards})
	if err != nil {
		return fmt.Errorf("idset save meta: %w", err)
	}

	for i := range s.shards {
		if !s.dirty[i] {
			continue
		}
		curr := s.curr[i]
		if len(curr) == 0 {
			err := store.Delete(shardKey(i))
			if err != nil {
				return fmt.Errorf("idset delete shard %d: %w", i, err)
			}
			continue
		}
		ids := make([]string, 0, len(curr))
		for id := range curr {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		err := store.Set(shardKey(i), ids)
		if err != nil {
			return fmt.Errorf("idset save shard %d: %w", i, err)
		}
	}
	return nil
}

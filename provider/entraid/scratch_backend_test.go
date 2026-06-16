// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package entraid

import (
	"cmp"
	"slices"
	"testing"
)

// TestScratchBackend_Integration exercises the bbolt-backed membershipGraph
// through the full write/read path including BFS traversal.
func TestScratchBackend_Integration(t *testing.T) {
	mg, err := newScratchBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer mg.close()

	for _, g := range []Group{
		{ID: "g1", DisplayName: "Group 1"},
		{ID: "g2", DisplayName: "Group 2"},
		{ID: "g3", DisplayName: "Group 3"},
	} {
		if err := mg.addGroup(g); err != nil {
			t.Fatalf("addGroup(%s): %v", g.ID, err)
		}
	}

	members := []struct {
		groupID string
		members []Member
	}{
		{"g1", []Member{
			{ID: "u1", Type: odataTypeUser},
			{ID: "d1", Type: odataTypeDevice},
		}},
		{"g2", []Member{
			{ID: "u1", Type: odataTypeUser},
			{ID: "g1", Type: odataTypeGroup},
		}},
		{"g3", []Member{
			{ID: "g2", Type: odataTypeGroup},
		}},
	}
	for _, m := range members {
		if err := mg.addMembers(m.groupID, m.members); err != nil {
			t.Fatalf("addMembers(%s): %v", m.groupID, err)
		}
	}

	gs, err := userTransitiveGroups(mg, "u1")
	if err != nil {
		t.Fatal(err)
	}
	sortGroups(gs)
	ids := groupIDs(gs)
	want := []string{"g1", "g2", "g3"}
	slices.Sort(want)
	if !slices.Equal(ids, want) {
		t.Errorf("userTransitiveGroups(u1) = %v; want %v", ids, want)
	}

	gs, err = deviceTransitiveGroups(mg, "d1")
	if err != nil {
		t.Fatal(err)
	}
	sortGroups(gs)
	ids = groupIDs(gs)
	want = []string{"g1", "g2", "g3"}
	slices.Sort(want)
	if !slices.Equal(ids, want) {
		t.Errorf("deviceTransitiveGroups(d1) = %v; want %v", ids, want)
	}
}

// TestScratchBackend_CycleDetection verifies BFS terminates with cycles.
func TestScratchBackend_CycleDetection(t *testing.T) {
	mg, err := newScratchBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer mg.close()

	for _, g := range []Group{
		{ID: "a", DisplayName: "A"},
		{ID: "b", DisplayName: "B"},
	} {
		if err := mg.addGroup(g); err != nil {
			t.Fatalf("addGroup(%s): %v", g.ID, err)
		}
	}
	if err := mg.addMembers("a", []Member{
		{ID: "u1", Type: odataTypeUser},
		{ID: "b", Type: odataTypeGroup},
	}); err != nil {
		t.Fatal(err)
	}
	if err := mg.addMembers("b", []Member{
		{ID: "a", Type: odataTypeGroup},
	}); err != nil {
		t.Fatal(err)
	}

	gs, err := userTransitiveGroups(mg, "u1")
	if err != nil {
		t.Fatal(err)
	}
	sortGroups(gs)
	if len(gs) != 2 || gs[0].ID != "a" || gs[1].ID != "b" {
		t.Errorf("cycle detection: got %v; want [a, b]", groupIDs(gs))
	}
}

// TestScratchBackend_RemovedMembers verifies removed members are skipped.
func TestScratchBackend_RemovedMembers(t *testing.T) {
	mg, err := newScratchBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer mg.close()

	if err := mg.addGroup(Group{ID: "g1", DisplayName: "G1"}); err != nil {
		t.Fatal(err)
	}
	if err := mg.addMembers("g1", []Member{
		{ID: "u1", Type: odataTypeUser},
		{ID: "u2", Type: odataTypeUser, Removed: &removed{Reason: "deleted"}},
	}); err != nil {
		t.Fatal(err)
	}

	gs, err := userTransitiveGroups(mg, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) != 1 || gs[0].ID != "g1" {
		t.Errorf("u1: got %v; want [g1]", groupIDs(gs))
	}
	gs, err = userTransitiveGroups(mg, "u2")
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) != 0 {
		t.Errorf("removed u2: got %v; want []", groupIDs(gs))
	}
}

// TestScratchBackend_GroupMetadata verifies group metadata round-trips.
func TestScratchBackend_GroupMetadata(t *testing.T) {
	mg, err := newScratchBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer mg.close()

	if err := mg.addGroup(Group{ID: "g1", DisplayName: "Engineering"}); err != nil {
		t.Fatal(err)
	}

	g, ok, err := mg.group("g1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected group g1 to exist")
	}
	if g.ID != "g1" || g.DisplayName != "Engineering" {
		t.Errorf("group = %+v; want {g1, Engineering}", g)
	}

	_, ok, err = mg.group("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected nonexistent group to return ok=false")
	}
}

// TestScratchBackend_MatchesMapBackend verifies that scratchBackend produces
// the same transitive groups as mapBackend for a complex topology.
func TestScratchBackend_MatchesMapBackend(t *testing.T) {
	groups := []Group{
		{ID: "leaf1", DisplayName: "Leaf1"},
		{ID: "leaf2", DisplayName: "Leaf2"},
		{ID: "mid", DisplayName: "Mid"},
		{ID: "top", DisplayName: "Top"},
	}
	memberMap := map[string][]Member{
		"leaf1": {
			{ID: "u1", Type: odataTypeUser},
			{ID: "d1", Type: odataTypeDevice},
		},
		"leaf2": {
			{ID: "u1", Type: odataTypeUser},
		},
		"mid": {
			{ID: "leaf1", Type: odataTypeGroup},
			{ID: "leaf2", Type: odataTypeGroup},
		},
		"top": {
			{ID: "mid", Type: odataTypeGroup},
		},
	}

	mb := newMapBackend()
	for _, g := range groups {
		mb.addGroup(g)
	}
	for gid, ms := range memberMap {
		mb.addMembers(gid, ms)
	}

	mg, err := newScratchBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer mg.close()
	for _, g := range groups {
		if err := mg.addGroup(g); err != nil {
			t.Fatalf("addGroup(%s): %v", g.ID, err)
		}
	}
	for gid, ms := range memberMap {
		if err := mg.addMembers(gid, ms); err != nil {
			t.Fatalf("addMembers(%s): %v", gid, err)
		}
	}

	for _, uid := range []string{"u1"} {
		mbGroups, err := userTransitiveGroups(mb, uid)
		if err != nil {
			t.Fatal(err)
		}
		sbGroups, err := userTransitiveGroups(mg, uid)
		if err != nil {
			t.Fatal(err)
		}
		sortGroups(mbGroups)
		sortGroups(sbGroups)
		mbIDs := groupIDs(mbGroups)
		sbIDs := groupIDs(sbGroups)
		slices.SortFunc(mbIDs, cmp.Compare[string])
		slices.SortFunc(sbIDs, cmp.Compare[string])
		if !slices.Equal(mbIDs, sbIDs) {
			t.Errorf("user %s: mapBackend=%v, scratchBackend=%v", uid, mbIDs, sbIDs)
		}
	}

	for _, did := range []string{"d1"} {
		mbGroups, err := deviceTransitiveGroups(mb, did)
		if err != nil {
			t.Fatal(err)
		}
		sbGroups, err := deviceTransitiveGroups(mg, did)
		if err != nil {
			t.Fatal(err)
		}
		sortGroups(mbGroups)
		sortGroups(sbGroups)
		mbIDs := groupIDs(mbGroups)
		sbIDs := groupIDs(sbGroups)
		slices.SortFunc(mbIDs, cmp.Compare[string])
		slices.SortFunc(sbIDs, cmp.Compare[string])
		if !slices.Equal(mbIDs, sbIDs) {
			t.Errorf("device %s: mapBackend=%v, scratchBackend=%v", did, mbIDs, sbIDs)
		}
	}
}

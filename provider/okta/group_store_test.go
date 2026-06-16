// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package okta

import (
	"cmp"
	"slices"
	"testing"
)

func TestGroupStore_RoundTrip(t *testing.T) {
	gs, err := newGroupStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer gs.Close()

	g1 := Group{ID: "gid1", Profile: map[string]any{"name": "Engineers"}}
	g2 := Group{ID: "gid2", Profile: map[string]any{"name": "Sales"}}

	if err := gs.addGroupMembers(g1, []User{
		{ID: "u1"},
		{ID: "u2"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := gs.addGroupMembers(g2, []User{
		{ID: "u1"},
		{ID: "u3"},
	}); err != nil {
		t.Fatal(err)
	}

	got, err := gs.groups("u1")
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(got, func(a, b Group) int { return cmp.Compare(a.ID, b.ID) })
	if len(got) != 2 || got[0].ID != "gid1" || got[1].ID != "gid2" {
		t.Errorf("groups(u1) = %v; want [gid1, gid2]", groupStoreIDs(got))
	}

	got, err = gs.groups("u2")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "gid1" {
		t.Errorf("groups(u2) = %v; want [gid1]", groupStoreIDs(got))
	}

	got, err = gs.groups("u3")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "gid2" {
		t.Errorf("groups(u3) = %v; want [gid2]", groupStoreIDs(got))
	}
}

func TestGroupStore_NoGroups(t *testing.T) {
	gs, err := newGroupStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer gs.Close()

	got, err := gs.groups("nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("groups(nonexistent) = %v; want nil", got)
	}
}

func TestGroupStore_ProfilePreserved(t *testing.T) {
	gs, err := newGroupStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer gs.Close()

	g := Group{
		ID:      "gid1",
		Profile: map[string]any{"name": "Engineering", "description": "eng team"},
	}
	if err := gs.addGroupMembers(g, []User{{ID: "u1"}}); err != nil {
		t.Fatal(err)
	}

	got, err := gs.groups("u1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("groups(u1) = %d groups; want 1", len(got))
	}
	if got[0].Profile["name"] != "Engineering" {
		t.Errorf("profile.name = %v; want Engineering", got[0].Profile["name"])
	}
}

func TestGroupStore_CloseNil(t *testing.T) {
	var gs *groupStore
	if err := gs.Close(); err != nil {
		t.Errorf("Close on nil groupStore should not error, got %v", err)
	}
}

func groupStoreIDs(groups []Group) []string {
	ids := make([]string, len(groups))
	for i, g := range groups {
		ids[i] = g.ID
	}
	return ids
}

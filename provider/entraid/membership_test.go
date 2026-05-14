// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package entraid

import (
	"cmp"
	"slices"
	"testing"
)

func TestMembershipGraph_DirectOnly(t *testing.T) {
	mg := newMembershipGraph()
	mg.addGroup(Group{ID: "g1", DisplayName: "Group 1"})
	mg.addGroup(Group{ID: "g2", DisplayName: "Group 2"})
	mg.addMembers("g1", []Member{
		{ID: "u1", Type: odataTypeUser},
	})
	mg.addMembers("g2", []Member{
		{ID: "u1", Type: odataTypeUser},
		{ID: "u2", Type: odataTypeUser},
	})

	gs := mg.userTransitiveGroups("u1")
	sortGroups(gs)
	if len(gs) != 2 || gs[0].ID != "g1" || gs[1].ID != "g2" {
		t.Errorf("u1 groups = %v; want [g1, g2]", groupIDs(gs))
	}

	gs = mg.userTransitiveGroups("u2")
	if len(gs) != 1 || gs[0].ID != "g2" {
		t.Errorf("u2 groups = %v; want [g2]", groupIDs(gs))
	}
}

func TestMembershipGraph_TwoLevelNesting(t *testing.T) {
	mg := newMembershipGraph()
	mg.addGroup(Group{ID: "child", DisplayName: "Child"})
	mg.addGroup(Group{ID: "parent", DisplayName: "Parent"})

	mg.addMembers("child", []Member{
		{ID: "u1", Type: odataTypeUser},
	})
	mg.addMembers("parent", []Member{
		{ID: "child", Type: odataTypeGroup},
	})

	gs := mg.userTransitiveGroups("u1")
	sortGroups(gs)
	if len(gs) != 2 || gs[0].ID != "child" || gs[1].ID != "parent" {
		t.Errorf("u1 groups = %v; want [child, parent]", groupIDs(gs))
	}
}

func TestMembershipGraph_DeepNesting(t *testing.T) {
	mg := newMembershipGraph()
	mg.addGroup(Group{ID: "a", DisplayName: "A"})
	mg.addGroup(Group{ID: "b", DisplayName: "B"})
	mg.addGroup(Group{ID: "c", DisplayName: "C"})
	mg.addGroup(Group{ID: "d", DisplayName: "D"})

	mg.addMembers("a", []Member{{ID: "u1", Type: odataTypeUser}})
	mg.addMembers("b", []Member{{ID: "a", Type: odataTypeGroup}})
	mg.addMembers("c", []Member{{ID: "b", Type: odataTypeGroup}})
	mg.addMembers("d", []Member{{ID: "c", Type: odataTypeGroup}})

	gs := mg.userTransitiveGroups("u1")
	sortGroups(gs)
	ids := groupIDs(gs)
	want := []string{"a", "b", "c", "d"}
	if len(ids) != 4 {
		t.Fatalf("u1 groups = %v; want %v", ids, want)
	}
	for i, id := range ids {
		if id != want[i] {
			t.Errorf("u1 groups[%d] = %s; want %s", i, id, want[i])
		}
	}
}

func TestMembershipGraph_CycleDetection(t *testing.T) {
	mg := newMembershipGraph()
	mg.addGroup(Group{ID: "a", DisplayName: "A"})
	mg.addGroup(Group{ID: "b", DisplayName: "B"})

	mg.addMembers("a", []Member{
		{ID: "u1", Type: odataTypeUser},
		{ID: "b", Type: odataTypeGroup},
	})
	mg.addMembers("b", []Member{
		{ID: "a", Type: odataTypeGroup},
	})

	gs := mg.userTransitiveGroups("u1")
	sortGroups(gs)
	if len(gs) != 2 || gs[0].ID != "a" || gs[1].ID != "b" {
		t.Errorf("u1 groups = %v; want [a, b] (cycle should not loop)", groupIDs(gs))
	}
}

func TestMembershipGraph_SharedParent(t *testing.T) {
	mg := newMembershipGraph()
	mg.addGroup(Group{ID: "x", DisplayName: "X"})
	mg.addGroup(Group{ID: "y", DisplayName: "Y"})
	mg.addGroup(Group{ID: "top", DisplayName: "Top"})

	mg.addMembers("x", []Member{{ID: "u1", Type: odataTypeUser}})
	mg.addMembers("y", []Member{{ID: "u1", Type: odataTypeUser}})
	mg.addMembers("top", []Member{
		{ID: "x", Type: odataTypeGroup},
		{ID: "y", Type: odataTypeGroup},
	})

	gs := mg.userTransitiveGroups("u1")
	sortGroups(gs)
	if len(gs) != 3 {
		t.Fatalf("u1 groups = %v; want [top, x, y]", groupIDs(gs))
	}
	if gs[0].ID != "top" || gs[1].ID != "x" || gs[2].ID != "y" {
		t.Errorf("u1 groups = %v; want [top, x, y]", groupIDs(gs))
	}
}

func TestMembershipGraph_DeviceMembership(t *testing.T) {
	mg := newMembershipGraph()
	mg.addGroup(Group{ID: "g1", DisplayName: "G1"})
	mg.addGroup(Group{ID: "g2", DisplayName: "G2"})

	mg.addMembers("g1", []Member{{ID: "d1", Type: odataTypeDevice}})
	mg.addMembers("g2", []Member{{ID: "g1", Type: odataTypeGroup}})

	gs := mg.deviceTransitiveGroups("d1")
	sortGroups(gs)
	if len(gs) != 2 || gs[0].ID != "g1" || gs[1].ID != "g2" {
		t.Errorf("d1 groups = %v; want [g1, g2]", groupIDs(gs))
	}
}

func TestMembershipGraph_RemovedMembersSkipped(t *testing.T) {
	mg := newMembershipGraph()
	mg.addGroup(Group{ID: "g1", DisplayName: "G1"})
	mg.addMembers("g1", []Member{
		{ID: "u1", Type: odataTypeUser},
		{ID: "u2", Type: odataTypeUser, Removed: &removed{Reason: "deleted"}},
	})

	gs := mg.userTransitiveGroups("u1")
	if len(gs) != 1 || gs[0].ID != "g1" {
		t.Errorf("u1 groups = %v; want [g1]", groupIDs(gs))
	}
	gs = mg.userTransitiveGroups("u2")
	if len(gs) != 0 {
		t.Errorf("removed member u2 groups = %v; want []", groupIDs(gs))
	}
}

func TestMembershipGraph_NoGroups(t *testing.T) {
	mg := newMembershipGraph()
	gs := mg.userTransitiveGroups("u1")
	if gs != nil {
		t.Errorf("unknown user groups = %v; want nil", gs)
	}
}

func sortGroups(gs []GroupECS) {
	slices.SortFunc(gs, func(a, b GroupECS) int { return cmp.Compare(a.ID, b.ID) })
}

func groupIDs(gs []GroupECS) []string {
	ids := make([]string, len(gs))
	for i, g := range gs {
		ids[i] = g.ID
	}
	return ids
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package entraid

import (
	"cmp"
	"fmt"
	"slices"
	"testing"
)

func TestMembershipGraph_DirectOnly(t *testing.T) {
	mg := newMapBackend()
	mg.addGroup(Group{ID: "g1", DisplayName: "Group 1"})
	mg.addGroup(Group{ID: "g2", DisplayName: "Group 2"})
	mg.addMembers("g1", []Member{
		{ID: "u1", Type: odataTypeUser},
	})
	mg.addMembers("g2", []Member{
		{ID: "u1", Type: odataTypeUser},
		{ID: "u2", Type: odataTypeUser},
	})

	gs, err := userTransitiveGroups(mg, "u1")
	if err != nil {
		t.Fatal(err)
	}
	sortGroups(gs)
	if len(gs) != 2 || gs[0].ID != "g1" || gs[1].ID != "g2" {
		t.Errorf("u1 groups = %v; want [g1, g2]", groupIDs(gs))
	}

	gs, err = userTransitiveGroups(mg, "u2")
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) != 1 || gs[0].ID != "g2" {
		t.Errorf("u2 groups = %v; want [g2]", groupIDs(gs))
	}
}

func TestMembershipGraph_TwoLevelNesting(t *testing.T) {
	mg := newMapBackend()
	mg.addGroup(Group{ID: "child", DisplayName: "Child"})
	mg.addGroup(Group{ID: "parent", DisplayName: "Parent"})

	mg.addMembers("child", []Member{
		{ID: "u1", Type: odataTypeUser},
	})
	mg.addMembers("parent", []Member{
		{ID: "child", Type: odataTypeGroup},
	})

	gs, err := userTransitiveGroups(mg, "u1")
	if err != nil {
		t.Fatal(err)
	}
	sortGroups(gs)
	if len(gs) != 2 || gs[0].ID != "child" || gs[1].ID != "parent" {
		t.Errorf("u1 groups = %v; want [child, parent]", groupIDs(gs))
	}
}

func TestMembershipGraph_DeepNesting(t *testing.T) {
	mg := newMapBackend()
	mg.addGroup(Group{ID: "a", DisplayName: "A"})
	mg.addGroup(Group{ID: "b", DisplayName: "B"})
	mg.addGroup(Group{ID: "c", DisplayName: "C"})
	mg.addGroup(Group{ID: "d", DisplayName: "D"})

	mg.addMembers("a", []Member{{ID: "u1", Type: odataTypeUser}})
	mg.addMembers("b", []Member{{ID: "a", Type: odataTypeGroup}})
	mg.addMembers("c", []Member{{ID: "b", Type: odataTypeGroup}})
	mg.addMembers("d", []Member{{ID: "c", Type: odataTypeGroup}})

	gs, err := userTransitiveGroups(mg, "u1")
	if err != nil {
		t.Fatal(err)
	}
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
	mg := newMapBackend()
	mg.addGroup(Group{ID: "a", DisplayName: "A"})
	mg.addGroup(Group{ID: "b", DisplayName: "B"})

	mg.addMembers("a", []Member{
		{ID: "u1", Type: odataTypeUser},
		{ID: "b", Type: odataTypeGroup},
	})
	mg.addMembers("b", []Member{
		{ID: "a", Type: odataTypeGroup},
	})

	gs, err := userTransitiveGroups(mg, "u1")
	if err != nil {
		t.Fatal(err)
	}
	sortGroups(gs)
	if len(gs) != 2 || gs[0].ID != "a" || gs[1].ID != "b" {
		t.Errorf("u1 groups = %v; want [a, b] (cycle should not loop)", groupIDs(gs))
	}
}

func TestMembershipGraph_SharedParent(t *testing.T) {
	mg := newMapBackend()
	mg.addGroup(Group{ID: "x", DisplayName: "X"})
	mg.addGroup(Group{ID: "y", DisplayName: "Y"})
	mg.addGroup(Group{ID: "top", DisplayName: "Top"})

	mg.addMembers("x", []Member{{ID: "u1", Type: odataTypeUser}})
	mg.addMembers("y", []Member{{ID: "u1", Type: odataTypeUser}})
	mg.addMembers("top", []Member{
		{ID: "x", Type: odataTypeGroup},
		{ID: "y", Type: odataTypeGroup},
	})

	gs, err := userTransitiveGroups(mg, "u1")
	if err != nil {
		t.Fatal(err)
	}
	sortGroups(gs)
	if len(gs) != 3 {
		t.Fatalf("u1 groups = %v; want [top, x, y]", groupIDs(gs))
	}
	if gs[0].ID != "top" || gs[1].ID != "x" || gs[2].ID != "y" {
		t.Errorf("u1 groups = %v; want [top, x, y]", groupIDs(gs))
	}
}

func TestMembershipGraph_DeviceMembership(t *testing.T) {
	mg := newMapBackend()
	mg.addGroup(Group{ID: "g1", DisplayName: "G1"})
	mg.addGroup(Group{ID: "g2", DisplayName: "G2"})

	mg.addMembers("g1", []Member{{ID: "d1", Type: odataTypeDevice}})
	mg.addMembers("g2", []Member{{ID: "g1", Type: odataTypeGroup}})

	gs, err := deviceTransitiveGroups(mg, "d1")
	if err != nil {
		t.Fatal(err)
	}
	sortGroups(gs)
	if len(gs) != 2 || gs[0].ID != "g1" || gs[1].ID != "g2" {
		t.Errorf("d1 groups = %v; want [g1, g2]", groupIDs(gs))
	}
}

func TestMembershipGraph_RemovedMembersSkipped(t *testing.T) {
	mg := newMapBackend()
	mg.addGroup(Group{ID: "g1", DisplayName: "G1"})
	mg.addMembers("g1", []Member{
		{ID: "u1", Type: odataTypeUser},
		{ID: "u2", Type: odataTypeUser, Removed: &removed{Reason: "deleted"}},
	})

	gs, err := userTransitiveGroups(mg, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) != 1 || gs[0].ID != "g1" {
		t.Errorf("u1 groups = %v; want [g1]", groupIDs(gs))
	}
	gs, err = userTransitiveGroups(mg, "u2")
	if err != nil {
		t.Fatal(err)
	}
	if len(gs) != 0 {
		t.Errorf("removed member u2 groups = %v; want []", groupIDs(gs))
	}
}

func TestMembershipGraph_NoGroups(t *testing.T) {
	mg := newMapBackend()
	gs, err := userTransitiveGroups(mg, "u1")
	if err != nil {
		t.Fatal(err)
	}
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

func BenchmarkMembershipGraph_Build(b *testing.B) {
	for _, tc := range []struct {
		name string
		gen  func() generatedGraph
	}{
		{"flat/groups=100/members=10", func() generatedGraph { return generateFlatGroups(100, 10, 100) }},
		{"flat/groups=1000/members=10", func() generatedGraph { return generateFlatGroups(1000, 10, 1000) }},
		{"flat/groups=10000/members=10", func() generatedGraph { return generateFlatGroups(10000, 10, 1000) }},
		{"flat/groups=1000/members=100", func() generatedGraph { return generateFlatGroups(1000, 100, 1000) }},
		{"chain/depth=3", func() generatedGraph { return generateNestedChain(3, 100) }},
		{"chain/depth=10", func() generatedGraph { return generateNestedChain(10, 100) }},
		{"chain/depth=100", func() generatedGraph { return generateNestedChain(100, 100) }},
		{"tree/fanout=3/depth=3", func() generatedGraph { return generateNestedTree(3, 3, 10) }},
		{"tree/fanout=3/depth=5", func() generatedGraph { return generateNestedTree(3, 5, 2) }},
		{"diamond/leaves=50/parents=50", func() generatedGraph { return generateDiamondGroups(50, 50, 100) }},
		{"diamond/leaves=100/parents=100", func() generatedGraph { return generateDiamondGroups(100, 100, 100) }},
	} {
		b.Run(tc.name, func(b *testing.B) {
			gg := tc.gen()
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				buildTestGraph(gg)
			}
		})
	}
}

func BenchmarkMembershipGraph_UserTransitiveGroups(b *testing.B) {
	for _, tc := range []struct {
		name string
		gen  func() generatedGraph
	}{
		{"flat/groups=100/direct=5", func() generatedGraph { return generateFlatGroups(100, 10, 100) }},
		{"flat/groups=1000/direct=5", func() generatedGraph { return generateFlatGroups(1000, 10, 1000) }},
		{"flat/groups=10000/direct=5", func() generatedGraph { return generateFlatGroups(10000, 10, 1000) }},
		{"chain/depth=10", func() generatedGraph { return generateNestedChain(10, 1) }},
		{"chain/depth=100", func() generatedGraph { return generateNestedChain(100, 1) }},
		{"tree/fanout=3/depth=5", func() generatedGraph { return generateNestedTree(3, 5, 1) }},
		{"diamond/leaves=50/parents=50", func() generatedGraph { return generateDiamondGroups(50, 50, 1) }},
		{"diamond/leaves=100/parents=100", func() generatedGraph { return generateDiamondGroups(100, 100, 1) }},
	} {
		b.Run(tc.name, func(b *testing.B) {
			gg := tc.gen()
			mg := buildTestGraph(gg)
			uid := gg.userIDs[0]
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				userTransitiveGroups(mg, uid)
			}
		})
	}
}

func BenchmarkMembershipGraph_AllUsers(b *testing.B) {
	for _, tc := range []struct {
		name string
		gen  func() generatedGraph
	}{
		{"users=100/groups=100/flat", func() generatedGraph { return generateFlatGroups(100, 10, 100) }},
		{"users=1000/groups=100/flat", func() generatedGraph { return generateFlatGroups(100, 10, 1000) }},
		{"users=1000/groups=1000/flat", func() generatedGraph { return generateFlatGroups(1000, 10, 1000) }},
		{"users=1000/groups=10000/flat", func() generatedGraph { return generateFlatGroups(10000, 10, 1000) }},
		{"users=100/chain/depth=10", func() generatedGraph { return generateNestedChain(10, 100) }},
		{"users=100/diamond/leaves=50/parents=50", func() generatedGraph { return generateDiamondGroups(50, 50, 100) }},
	} {
		b.Run(tc.name, func(b *testing.B) {
			gg := tc.gen()
			mg := buildTestGraph(gg)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				for _, uid := range gg.userIDs {
					userTransitiveGroups(mg, uid)
				}
			}
		})
	}
}

type generatedGraph struct {
	groups  []Group
	members map[string][]Member
	userIDs []string
}

// generateFlatGroups builds nGroups flat (non-nested) groups, each with
// usersPerGroup user members. Users are reused cyclically from a pool of
// nUsers unique IDs, so a user can appear in multiple groups.
func generateFlatGroups(nGroups, usersPerGroup, nUsers int) generatedGraph {
	groups := make([]Group, nGroups)
	members := make(map[string][]Member, nGroups)
	for i := range nGroups {
		gid := fmt.Sprintf("g%d", i)
		groups[i] = Group{ID: gid, DisplayName: gid}
		ms := make([]Member, usersPerGroup)
		for j := range usersPerGroup {
			ms[j] = Member{ID: fmt.Sprintf("u%d", j%nUsers), Type: odataTypeUser}
		}
		members[gid] = ms
	}
	userIDs := make([]string, nUsers)
	for i := range nUsers {
		userIDs[i] = fmt.Sprintf("u%d", i)
	}
	return generatedGraph{groups: groups, members: members, userIDs: userIDs}
}

// generateNestedChain builds a linear chain of depth groups: g0 → g1 → … → g(depth-1).
// A single user is a member of g0 (the leaf). Transitive membership reaches
// all groups up the chain.
func generateNestedChain(depth, nUsers int) generatedGraph {
	groups := make([]Group, depth)
	members := make(map[string][]Member, depth)
	for i := range depth {
		gid := fmt.Sprintf("g%d", i)
		groups[i] = Group{ID: gid, DisplayName: gid}
	}
	// Users are direct members of g0.
	ms := make([]Member, nUsers)
	userIDs := make([]string, nUsers)
	for i := range nUsers {
		uid := fmt.Sprintf("u%d", i)
		ms[i] = Member{ID: uid, Type: odataTypeUser}
		userIDs[i] = uid
	}
	members[groups[0].ID] = ms
	// Each group is nested in the next: g0 is a member of g1, g1 of g2, etc.
	for i := range depth - 1 {
		members[groups[i+1].ID] = append(members[groups[i+1].ID], Member{
			ID:   groups[i].ID,
			Type: odataTypeGroup,
		})
	}
	return generatedGraph{groups: groups, members: members, userIDs: userIDs}
}

// generateNestedTree builds a tree of groups with the given branching factor
// (fanout) and depth. Users are placed in every leaf group. Total groups =
// (fanout^depth - 1) / (fanout - 1) for fanout > 1, or depth for fanout == 1.
func generateNestedTree(fanout, depth, nUsersPerLeaf int) generatedGraph {
	var groups []Group
	members := make(map[string][]Member)
	var userIDs []string
	uid := 0

	var build func(level int) string
	gid := 0
	build = func(level int) string {
		id := fmt.Sprintf("g%d", gid)
		gid++
		groups = append(groups, Group{ID: id, DisplayName: id})
		if level == depth-1 {
			ms := make([]Member, nUsersPerLeaf)
			for i := range nUsersPerLeaf {
				u := fmt.Sprintf("u%d", uid)
				ms[i] = Member{ID: u, Type: odataTypeUser}
				userIDs = append(userIDs, u)
				uid++
			}
			members[id] = ms
			return id
		}
		for range fanout {
			childID := build(level + 1)
			members[id] = append(members[id], Member{ID: childID, Type: odataTypeGroup})
		}
		return id
	}
	build(0)
	return generatedGraph{groups: groups, members: members, userIDs: userIDs}
}

// generateDiamondGroups builds nGroups groups arranged so that many groups
// share common parent groups, creating diamond/DAG patterns that maximise
// BFS revisit attempts. The first half are leaf groups containing users;
// the second half are parent groups each containing all leaf groups as
// nested members.
func generateDiamondGroups(nLeaves, nParents, nUsers int) generatedGraph {
	groups := make([]Group, 0, nLeaves+nParents)
	members := make(map[string][]Member)
	userIDs := make([]string, nUsers)

	for i := range nUsers {
		userIDs[i] = fmt.Sprintf("u%d", i)
	}

	// Leaf groups: each contains all users.
	leaves := make([]string, nLeaves)
	for i := range nLeaves {
		gid := fmt.Sprintf("leaf%d", i)
		leaves[i] = gid
		groups = append(groups, Group{ID: gid, DisplayName: gid})
		ms := make([]Member, nUsers)
		for j := range nUsers {
			ms[j] = Member{ID: userIDs[j], Type: odataTypeUser}
		}
		members[gid] = ms
	}

	// Parent groups: each contains all leaves as nested group members.
	for i := range nParents {
		gid := fmt.Sprintf("parent%d", i)
		groups = append(groups, Group{ID: gid, DisplayName: gid})
		ms := make([]Member, nLeaves)
		for j := range nLeaves {
			ms[j] = Member{ID: leaves[j], Type: odataTypeGroup}
		}
		members[gid] = ms
	}

	return generatedGraph{groups: groups, members: members, userIDs: userIDs}
}

// buildTestGraph populates a mapBackend from a generatedGraph fixture.
func buildTestGraph(gg generatedGraph) *mapBackend {
	mg := newMapBackend()
	for _, g := range gg.groups {
		mg.addGroup(g)
	}
	for gid, ms := range gg.members {
		mg.addMembers(gid, ms)
	}
	return mg
}

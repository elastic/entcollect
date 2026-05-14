// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package entraid

// membershipGraph computes transitive group membership from an
// in-memory snapshot of groups and their members. It is built fresh
// each sync and discarded after.
type membershipGraph struct {
	groups       map[string]Group
	userGroups   idGraph // user ID → direct group IDs
	deviceGroups idGraph // device ID → direct group IDs
	parentOf     idGraph // subgroup ID → parent group IDs
}

func newMembershipGraph() *membershipGraph {
	return &membershipGraph{
		groups:       make(map[string]Group),
		userGroups:   make(idGraph),
		deviceGroups: make(idGraph),
		parentOf:     make(idGraph),
	}
}

// addGroup registers a group in the graph.
func (mg *membershipGraph) addGroup(g Group) {
	mg.groups[g.ID] = g
}

// addMembers records the membership edges for a group's member list.
func (mg *membershipGraph) addMembers(groupID string, members []Member) {
	for _, m := range members {
		if m.Removed != nil {
			continue
		}
		switch m.Type {
		case odataTypeUser:
			mg.userGroups.link(m.ID, groupID)
		case odataTypeDevice:
			mg.deviceGroups.link(m.ID, groupID)
		case odataTypeGroup:
			mg.parentOf.link(m.ID, groupID)
		}
	}
}

// GroupECS is the ECS-compatible group representation emitted in
// Document.Fields under "user.group" or "device.group".
type GroupECS struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// userTransitiveGroups returns all transitive groups for a user.
func (mg *membershipGraph) userTransitiveGroups(userID string) []GroupECS {
	direct := mg.userGroups[userID]
	if len(direct) == 0 {
		return nil
	}
	return mg.expandTransitive(direct)
}

// deviceTransitiveGroups returns all transitive groups for a device.
func (mg *membershipGraph) deviceTransitiveGroups(deviceID string) []GroupECS {
	direct := mg.deviceGroups[deviceID]
	if len(direct) == 0 {
		return nil
	}
	return mg.expandTransitive(direct)
}

// expandTransitive walks from a set of direct group IDs through the
// parentOf graph, collecting all reachable groups. Uses a BFS with a
// seen set to handle cycles defensively.
func (mg *membershipGraph) expandTransitive(directIDs map[string]struct{}) []GroupECS {
	seen := make(map[string]struct{}, len(directIDs))
	queue := make([]string, 0, len(directIDs))
	for id := range directIDs {
		queue = append(queue, id)
		seen[id] = struct{}{}
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for parent := range mg.parentOf[current] {
			if _, ok := seen[parent]; ok {
				continue
			}
			seen[parent] = struct{}{}
			queue = append(queue, parent)
		}
	}

	result := make([]GroupECS, 0, len(seen))
	for id := range seen {
		if g, ok := mg.groups[id]; ok {
			result = append(result, GroupECS{ID: g.ID, Name: g.DisplayName})
		}
	}
	return result
}

// idGraph is a directed adjacency set: from → set of to.
type idGraph map[string]map[string]struct{}

// link adds a directed edge from → to.
func (g idGraph) link(from, to string) {
	s := g[from]
	if s == nil {
		s = make(map[string]struct{})
		g[from] = s
	}
	s[to] = struct{}{}
}

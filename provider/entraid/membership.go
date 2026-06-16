// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package entraid

import (
	"maps"
	"slices"
	"strings"
)

// membershipGraph abstracts storage for the membership graph. Production
// uses a bbolt-backed implementation; tests use a map-backed double.
type membershipGraph interface {
	// addGroup stores group metadata.
	addGroup(g Group) error

	// addMembers records membership edges for a group's member list.
	// Members with a non-nil Removed field are skipped.
	addMembers(groupID string, members []Member) error

	// directUserGroups returns the IDs of groups the user belongs to directly.
	directUserGroups(userID string) ([]string, error)

	// directDeviceGroups returns the IDs of groups the device belongs to directly.
	directDeviceGroups(deviceID string) ([]string, error)

	// parentGroups returns the IDs of groups that contain subgroupID as a member.
	parentGroups(subgroupID string) ([]string, error)

	// group returns the metadata for a group by ID.
	group(id string) (Group, bool, error)

	// close releases resources. For bbolt-backed storage this removes
	// the temporary file. For the map backend this is a no-op.
	close() error
}

// GroupECS is the ECS-compatible group representation emitted in
// Document.Fields under "user.group" or "device.group".
type GroupECS struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// userTransitiveGroups returns all transitive groups for a user,
// reading adjacency data through the backend.
func userTransitiveGroups(b membershipGraph, userID string) ([]GroupECS, error) {
	direct, err := b.directUserGroups(userID)
	if err != nil {
		return nil, err
	}
	if len(direct) == 0 {
		return nil, nil
	}
	return expandTransitive(b, direct)
}

// deviceTransitiveGroups returns all transitive groups for a device.
func deviceTransitiveGroups(b membershipGraph, deviceID string) ([]GroupECS, error) {
	direct, err := b.directDeviceGroups(deviceID)
	if err != nil {
		return nil, err
	}
	if len(direct) == 0 {
		return nil, nil
	}
	return expandTransitive(b, direct)
}

// expandTransitive walks from a set of direct group IDs through the
// parent graph, collecting all reachable groups. Uses BFS with a
// seen set to handle cycles defensively.
func expandTransitive(b membershipGraph, directIDs []string) ([]GroupECS, error) {
	seen := make(map[string]struct{}, len(directIDs))
	queue := make([]string, 0, len(directIDs))
	for _, id := range directIDs {
		queue = append(queue, id)
		seen[id] = struct{}{}
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		parents, err := b.parentGroups(current)
		if err != nil {
			return nil, err
		}
		for _, parent := range parents {
			if _, ok := seen[parent]; ok {
				continue
			}
			seen[parent] = struct{}{}
			queue = append(queue, parent)
		}
	}

	result := make([]GroupECS, 0, len(seen))
	for id := range seen {
		g, ok, err := b.group(id)
		if err != nil {
			return nil, err
		}
		if ok {
			result = append(result, GroupECS{ID: g.ID, Name: g.DisplayName})
		}
	}
	slices.SortFunc(result, func(a, b GroupECS) int {
		return strings.Compare(a.ID, b.ID)
	})
	return result, nil
}

// mapBackend is the in-memory implementation of membershipGraph, used as
// a test double. It preserves the original map-based adjacency design.
type mapBackend struct {
	groups       map[string]Group
	userGroups   idGraph
	deviceGroups idGraph
	parentOf     idGraph
}

var _ membershipGraph = (*mapBackend)(nil)

func newMapBackend() *mapBackend {
	return &mapBackend{
		groups:       make(map[string]Group),
		userGroups:   make(idGraph),
		deviceGroups: make(idGraph),
		parentOf:     make(idGraph),
	}
}

// addGroup implements membershipGraph.addGroup by storing in a map.
func (mg *mapBackend) addGroup(g Group) error {
	mg.groups[g.ID] = g
	return nil
}

// addMembers implements membershipGraph.addMembers by inserting edges
// into the appropriate adjacency maps based on member type.
func (mg *mapBackend) addMembers(groupID string, members []Member) error {
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
	return nil
}

// directUserGroups implements membershipGraph.directUserGroups.
func (mg *mapBackend) directUserGroups(userID string) ([]string, error) {
	return slices.Collect(maps.Keys(mg.userGroups[userID])), nil
}

// directDeviceGroups implements membershipGraph.directDeviceGroups.
func (mg *mapBackend) directDeviceGroups(deviceID string) ([]string, error) {
	return slices.Collect(maps.Keys(mg.deviceGroups[deviceID])), nil
}

// parentGroups implements membershipGraph.parentGroups.
func (mg *mapBackend) parentGroups(subgroupID string) ([]string, error) {
	return slices.Collect(maps.Keys(mg.parentOf[subgroupID])), nil
}

// group implements membershipGraph.group.
func (mg *mapBackend) group(id string) (Group, bool, error) {
	g, ok := mg.groups[id]
	return g, ok, nil
}

// close implements membershipGraph.close (no-op for in-memory storage).
func (mg *mapBackend) close() error { return nil }

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

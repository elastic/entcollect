// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package okta

import (
	"github.com/elastic/entcollect/internal/scratch"
)

const (
	bucketOktaGroups     = "groups"
	bucketOktaUserGroups = "user_groups"
)

// groupStore wraps a scratch DB for bulk group-to-user mapping. It stores
// group metadata and edges from user IDs to group IDs, allowing per-user
// group lookup without holding the full mapping in memory.
type groupStore struct {
	db *scratch.DB
}

func newGroupStore(dir string) (*groupStore, error) {
	db, err := scratch.Open(dir)
	if err != nil {
		return nil, err
	}
	return &groupStore{db: db}, nil
}

// addGroupMembers records a group's metadata and creates an edge from
// each member to the group. This uses a single transaction per group.
func (gs *groupStore) addGroupMembers(g Group, members []User) error {
	return gs.db.BatchWrite(func(tx *scratch.Tx) error {
		if err := tx.PutJSON(bucketOktaGroups, g.ID, g); err != nil {
			return err
		}
		for _, m := range members {
			if err := tx.Link(bucketOktaUserGroups, m.ID, g.ID); err != nil {
				return err
			}
		}
		return nil
	})
}

// groups returns the groups a user belongs to by looking up edges and
// then fetching group metadata for each.
func (gs *groupStore) groups(userID string) ([]Group, error) {
	ids, err := gs.db.Neighbors(bucketOktaUserGroups, userID)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	result := make([]Group, 0, len(ids))
	for _, id := range ids {
		var g Group
		ok, err := gs.db.GetJSON(bucketOktaGroups, id, &g)
		if err != nil {
			return nil, err
		}
		if ok {
			result = append(result, g)
		}
	}
	return result, nil
}

// Close releases the scratch database and removes the temporary file.
func (gs *groupStore) Close() error {
	if gs == nil || gs.db == nil {
		return nil
	}
	return gs.db.Close()
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package entraid

import (
	"github.com/elastic/entcollect/internal/scratch"
)

const (
	bucketGroups       = "groups"
	bucketUserGroups   = "user_groups"
	bucketDeviceGroups = "device_groups"
	bucketParentOf     = "parent_of"
)

// scratchBackend implements membershipGraph using a temporary bbolt file.
type scratchBackend struct {
	db *scratch.DB
}

var _ membershipGraph = (*scratchBackend)(nil)

func newScratchBackend(dir string) (*scratchBackend, error) {
	db, err := scratch.Open(dir)
	if err != nil {
		return nil, err
	}
	return &scratchBackend{db: db}, nil
}

// addGroup implements membershipGraph.addGroup by writing group metadata
// as JSON into the groups bucket.
func (mg *scratchBackend) addGroup(g Group) error {
	return mg.db.PutJSON(bucketGroups, g.ID, g)
}

// addMembers implements membershipGraph.addMembers by writing all member
// edges for a group in a single bbolt transaction.
func (mg *scratchBackend) addMembers(groupID string, members []Member) error {
	return mg.db.BatchWrite(func(tx *scratch.Tx) error {
		for _, m := range members {
			if m.Removed != nil {
				continue
			}
			switch m.Type {
			case odataTypeUser:
				if err := tx.Link(bucketUserGroups, m.ID, groupID); err != nil {
					return err
				}
			case odataTypeDevice:
				if err := tx.Link(bucketDeviceGroups, m.ID, groupID); err != nil {
					return err
				}
			case odataTypeGroup:
				if err := tx.Link(bucketParentOf, m.ID, groupID); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// directUserGroups implements membershipGraph.directUserGroups.
func (mg *scratchBackend) directUserGroups(userID string) ([]string, error) {
	return mg.db.Neighbors(bucketUserGroups, userID)
}

// directDeviceGroups implements membershipGraph.directDeviceGroups.
func (mg *scratchBackend) directDeviceGroups(deviceID string) ([]string, error) {
	return mg.db.Neighbors(bucketDeviceGroups, deviceID)
}

// parentGroups implements membershipGraph.parentGroups.
func (mg *scratchBackend) parentGroups(subgroupID string) ([]string, error) {
	return mg.db.Neighbors(bucketParentOf, subgroupID)
}

// group implements membershipGraph.group.
func (mg *scratchBackend) group(id string) (Group, bool, error) {
	var g Group
	ok, err := mg.db.GetJSON(bucketGroups, id, &g)
	return g, ok, err
}

// close implements membershipGraph.close by closing and removing the
// temporary bbolt file.
func (mg *scratchBackend) close() error {
	return mg.db.Close()
}

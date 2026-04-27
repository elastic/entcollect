// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package jamf

import (
	"errors"
	"time"
)

// DefaultIDSetShards is the default number of shards used by the ID set for
// deletion detection. The value is small because Jamf tenants typically manage
// hundreds to tens of thousands of devices; a single shard would handle this
// range without difficulty. Sharding only matters if the store has strict
// per-value size limits.
const DefaultIDSetShards = 16

// Config holds the parameters for a Jamf provider. Fields use json tags for
// cross-runtime portability; each adapter maps its own config dialect onto
// this struct via a local mirror struct with the appropriate tags.
type Config struct {
	TenantID       string        `json:"jamf_tenant"`
	Username       string        `json:"jamf_username"`
	Password       string        `json:"jamf_password"`
	PageSize       int           `json:"page_size"`
	IDSetShards    int           `json:"idset_shards"`
	TokenGrace     time.Duration `json:"token_grace_period"`
	SyncInterval   time.Duration `json:"sync_interval"`
	UpdateInterval time.Duration `json:"update_interval"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		IDSetShards:    DefaultIDSetShards,
		SyncInterval:   24 * time.Hour,
		UpdateInterval: 15 * time.Minute,
		TokenGrace:     time.Minute,
	}
}

var (
	errMissingTenant       = errors.New("jamf_tenant is required")
	errMissingUsername     = errors.New("jamf_username is required")
	errMissingPassword     = errors.New("jamf_password is required")
	errInvalidSync         = errors.New("sync_interval must be positive")
	errInvalidUpdate       = errors.New("update_interval must be positive")
	errSyncNotLonger       = errors.New("sync_interval must be greater than update_interval")
)

// Validate returns an error if the Config is invalid.
func (c *Config) Validate() error {
	switch {
	case c.TenantID == "":
		return errMissingTenant
	case c.Username == "":
		return errMissingUsername
	case c.Password == "":
		return errMissingPassword
	case c.SyncInterval <= 0:
		return errInvalidSync
	case c.UpdateInterval <= 0:
		return errInvalidUpdate
	case c.SyncInterval <= c.UpdateInterval:
		return errSyncNotLonger
	}
	return nil
}

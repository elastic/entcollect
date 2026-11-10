// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package jamf

import (
	"errors"
	"net/url"
	"strconv"
	"strings"
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
	errMissingTenant   = errors.New("jamf_tenant is required")
	errInvalidTenant   = errors.New("jamf_tenant must be only a host, with an optional port: no scheme, user information, path, query or fragment")
	errMissingUsername = errors.New("jamf_username is required")
	errMissingPassword = errors.New("jamf_password is required")
	errInvalidPageSize = errors.New("page_size must not be negative")
	errInvalidShards   = errors.New("idset_shards must be at least 1")
	errInvalidGrace    = errors.New("token_grace_period must not be negative")
	errInvalidSync     = errors.New("sync_interval must be positive")
	errInvalidUpdate   = errors.New("update_interval must be positive")
	errSyncNotLonger   = errors.New("sync_interval must be greater than update_interval")
)

// Validate returns an error if the Config is invalid.
func (c *Config) Validate() error {
	switch {
	case c.TenantID == "":
		return errMissingTenant
	case !validHost(c.TenantID):
		return errInvalidTenant
	case c.Username == "":
		return errMissingUsername
	case c.Password == "":
		return errMissingPassword
	case c.PageSize < 0:
		return errInvalidPageSize
	case c.IDSetShards < 1:
		return errInvalidShards
	case c.TokenGrace < 0:
		return errInvalidGrace
	case c.SyncInterval <= 0:
		return errInvalidSync
	case c.UpdateInterval <= 0:
		return errInvalidUpdate
	case c.SyncInterval <= c.UpdateInterval:
		return errSyncNotLonger
	}
	return nil
}

// validHost reports whether s parses as exactly the host, with an optional
// port, of an https URL, so that it can be used as the host of the
// tenant's API URLs. Anything else in s, such as a scheme, user
// information or a path, makes the parsed host differ from s. An IPv6
// address must be in brackets, and a port must be a number from 1 to
// 65535. It does not check the syntax of the host name itself.
func validHost(s string) bool {
	u, err := url.Parse("https://" + s)
	if err != nil || u.Host != s || u.Hostname() == "" {
		return false
	}
	// Depending on the main module's Go version, url.Parse may accept an
	// unbracketed IPv6 address, taking its last group as the port.
	if !strings.HasPrefix(s, "[") && strings.Contains(u.Hostname(), ":") {
		return false
	}
	if strings.HasSuffix(s, ":") {
		return false
	}
	port := u.Port()
	if port == "" {
		return true
	}
	n, err := strconv.Atoi(port)
	return err == nil && 1 <= n && n <= 65535
}

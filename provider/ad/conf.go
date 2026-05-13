// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ad

import (
	"crypto/tls"
	"errors"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// DefaultIDSetShards is the default number of shards used by each ID set.
// AD syncs three independent ID sets (users, devices, groups), each prefixed
// to avoid key collisions.
const DefaultIDSetShards = 16

// Config holds the parameters for an Active Directory provider. Fields use
// json tags for cross-runtime portability; each adapter maps its own config
// dialect onto this struct via a local mirror with the appropriate tags.
type Config struct {
	URL      string `json:"ad_url"`
	BaseDN   string `json:"ad_base_dn"`
	User     string `json:"ad_user"`
	Password string `json:"ad_password"`

	Dataset            string   `json:"dataset"`
	UserQuery          string   `json:"user_query"`
	DeviceQuery        string   `json:"device_query"`
	IncludeEmptyGroups bool     `json:"include_empty_groups"`
	UserAttrs          []string `json:"user_attributes"`
	GrpAttrs           []string `json:"group_attributes"`
	PagingSize         uint32   `json:"ad_paging_size"`

	IDSetShards    int           `json:"idset_shards"`
	SyncInterval   time.Duration `json:"sync_interval"`
	UpdateInterval time.Duration `json:"update_interval"`

	// TLS is built by the adapter from its own TLS configuration
	// (tlscommon.Config in Beats, configtls in OTel). It is not
	// serialised to JSON.
	TLS *tls.Config `json:"-"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		IDSetShards:    DefaultIDSetShards,
		SyncInterval:   24 * time.Hour,
		UpdateInterval: 15 * time.Minute,
	}
}

var (
	errMissingURL      = errors.New("ad_url is required")
	errMissingBaseDN   = errors.New("ad_base_dn is required")
	errMissingUser     = errors.New("ad_user is required")
	errMissingPassword = errors.New("ad_password is required")
	errInvalidSync     = errors.New("sync_interval must be positive")
	errInvalidUpdate   = errors.New("update_interval must be positive")
	errSyncNotLonger   = errors.New("sync_interval must be greater than update_interval")
)

// Validate returns an error if the Config is invalid.
func (c *Config) Validate() error {
	switch {
	case c.URL == "":
		return errMissingURL
	case c.BaseDN == "":
		return errMissingBaseDN
	case c.User == "":
		return errMissingUser
	case c.Password == "":
		return errMissingPassword
	case c.SyncInterval <= 0:
		return errInvalidSync
	case c.UpdateInterval <= 0:
		return errInvalidUpdate
	case c.SyncInterval <= c.UpdateInterval:
		return errSyncNotLonger
	}
	switch strings.ToLower(c.Dataset) {
	case "", "all", "users", "devices":
	default:
		return errors.New("dataset must be 'all', 'users', 'devices' or empty")
	}
	_, err := ldap.ParseDN(c.BaseDN)
	if err != nil {
		return err
	}
	return nil
}

// withMandatory ensures attrs contains the listed names. If attrs is
// nil or empty the LDAP search returns all attributes, so nothing is added.
func withMandatory(attrs []string, include ...string) []string {
	if len(attrs) == 0 {
		return nil
	}
outer:
	for _, m := range include {
		for _, a := range attrs {
			if m == a {
				continue outer
			}
		}
		attrs = append(attrs, m)
	}
	return attrs
}

func (c *Config) wantUsers() bool {
	switch strings.ToLower(c.Dataset) {
	case "", "all", "users":
		return true
	default:
		return false
	}
}

func (c *Config) wantDevices() bool {
	switch strings.ToLower(c.Dataset) {
	case "", "all", "devices":
		return true
	default:
		return false
	}
}

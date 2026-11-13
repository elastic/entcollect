// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package okta

import (
	"errors"
	"strings"
	"time"

	"github.com/elastic/entcollect/internal/urlhost"
)

// DefaultIDSetShards is the default number of shards used by each ID set.
// Okta syncs two independent ID sets (users, devices), each prefixed to
// avoid key collisions.
const DefaultIDSetShards = 16

// Config holds the parameters for the Okta provider. Fields use json tags
// for cross-runtime portability; each adapter maps its own config dialect
// onto this struct.
type Config struct {
	// Domain is the Okta organization's host, such as example.okta.com,
	// with an optional port. An https:// prefix is accepted and removed.
	Domain string `json:"okta_domain"`
	Token  string `json:"okta_token"`

	OAuth2 *OAuth2Config `json:"oauth2,omitempty"`

	// Dataset controls which entity kinds are synced: "", "all", "users",
	// or "devices". Empty and "all" are equivalent and sync both.
	Dataset string `json:"dataset"`

	// EnrichWith controls optional per-user enrichment. Valid values:
	// groups, factors, roles, permissions, devices, supervises, none.
	EnrichWith []string `json:"enrich_with"`

	// BatchSize is the page size for full-sync user, group and group
	// member listings. Zero uses the API's default. It must not be
	// negative.
	BatchSize      int           `json:"batch_size"`
	SyncInterval   time.Duration `json:"sync_interval"`
	UpdateInterval time.Duration `json:"update_interval"`

	// IDSetShards is the number of shards in each ID set. It must be at
	// least 1.
	IDSetShards int `json:"idset_shards"`

	// LimitWindow is the time between Okta API rate limit resets, and
	// LimitFixed, if set, is the number of requests allowed to each
	// endpoint in each window, in place of the limits Okta reports. Both
	// must be positive.
	LimitWindow time.Duration `json:"limit_window"`
	LimitFixed  *int          `json:"limit_fixed"`

	// ScratchDir is the directory for temporary scratch files used during
	// enrichment computation. Defaults to os.TempDir() when empty.
	ScratchDir string `json:"scratch_dir"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		EnrichWith:     []string{"groups"},
		SyncInterval:   24 * time.Hour,
		UpdateInterval: 15 * time.Minute,
		IDSetShards:    DefaultIDSetShards,
		LimitWindow:    time.Minute,
	}
}

var (
	errMissingDomain     = errors.New("okta_domain is required")
	errInvalidDomain     = errors.New("okta_domain must be a host name with an optional port, such as example.okta.com or https://example.okta.com, with no path, query, user information or other scheme")
	errNoAuth            = errors.New("exactly one of okta_token or oauth2 is required")
	errBothAuth          = errors.New("cannot specify both okta_token and oauth2")
	errInvalidBatchSize  = errors.New("batch_size must not be negative")
	errInvalidShards     = errors.New("idset_shards must be at least 1")
	errInvalidWindow     = errors.New("limit_window must be positive")
	errInvalidFixed      = errors.New("limit_fixed must be positive if set")
	errInvalidSync       = errors.New("sync_interval must be positive")
	errInvalidUpdate     = errors.New("update_interval must be positive")
	errSyncNotLonger     = errors.New("sync_interval must be greater than update_interval")
	errInvalidDataset    = errors.New("dataset must be 'all', 'users', 'devices' or empty")
	errInvalidEnrichment = errors.New("unknown enrich_with value")

	errOAuth2MissingClientID = errors.New("oauth2: client_id is required")
	errOAuth2MissingTokenURL = errors.New("oauth2: token_url is required")
	errOAuth2InvalidTokenURL = errors.New("oauth2: token_url must be an absolute https URL, such as https://example.okta.com/oauth2/v1/token")
	errOAuth2MissingScopes   = errors.New("oauth2: scopes is required")
	errOAuth2NoCreds         = errors.New("oauth2: exactly one of client_secret or jwk is required")
	errOAuth2BothCreds       = errors.New("oauth2: cannot specify both client_secret and jwk")
)

var validEnrichments = map[string]bool{
	"groups":      true,
	"factors":     true,
	"roles":       true,
	"permissions": true,
	"devices":     true,
	"supervises":  true,
	"none":        true,
}

// Validate returns an error if the Config is invalid.
func (c *Config) Validate() error {
	switch {
	case c.Domain == "":
		return errMissingDomain
	case !urlhost.Valid(domainHost(c.Domain)):
		return errInvalidDomain
	case c.Token == "" && c.OAuth2 == nil:
		return errNoAuth
	case c.Token != "" && c.OAuth2 != nil:
		return errBothAuth
	case c.BatchSize < 0:
		return errInvalidBatchSize
	case c.IDSetShards < 1:
		return errInvalidShards
	case c.LimitWindow <= 0:
		return errInvalidWindow
	case c.LimitFixed != nil && *c.LimitFixed <= 0:
		return errInvalidFixed
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
		return errInvalidDataset
	}
	for _, e := range c.EnrichWith {
		if !validEnrichments[strings.ToLower(e)] {
			return errInvalidEnrichment
		}
	}
	if c.OAuth2 != nil {
		if err := c.OAuth2.validate(); err != nil {
			return err
		}
	}
	return nil
}

// domainHost returns domain without a leading https:// scheme, matched in
// any letter case. The Okta integration asks for the domain as a
// URL, such as https://example.okta.com, but requests use it as a host.
func domainHost(domain string) string {
	const scheme = "https://"
	if len(domain) >= len(scheme) && strings.EqualFold(domain[:len(scheme)], scheme) {
		return domain[len(scheme):]
	}
	return domain
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

func (c *Config) enrichmentSet() map[string]bool {
	m := make(map[string]bool, len(c.EnrichWith))
	for _, e := range c.EnrichWith {
		m[strings.ToLower(e)] = true
	}
	return m
}

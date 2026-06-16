// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package entraid

import (
	"errors"
	"strings"
	"time"
)

// Config holds the parameters for the EntraID provider. Fields use json
// tags for cross-runtime portability; each adapter maps its own config
// dialect onto this struct.
type Config struct {
	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`

	LoginEndpoint string   `json:"login_endpoint"`
	LoginScopes   []string `json:"login_scopes"`
	APIEndpoint   string   `json:"api_endpoint"`

	// Dataset controls which entity kinds are synced: "", "all",
	// "users", or "devices". Empty and "all" are equivalent.
	Dataset string `json:"dataset"`

	// EnrichWith controls optional enrichment. Valid values: mfa, none.
	EnrichWith []string `json:"enrich_with"`

	SelectUsers   []string `json:"select_users"`
	SelectGroups  []string `json:"select_groups"`
	SelectDevices []string `json:"select_devices"`

	SyncInterval   time.Duration `json:"sync_interval"`
	UpdateInterval time.Duration `json:"update_interval"`

	// ScratchDir is the directory for temporary scratch files used during
	// enrichment computation. Defaults to os.TempDir() when empty.
	ScratchDir string `json:"scratch_dir"`
}

const (
	defaultLoginEndpoint = "https://login.microsoftonline.com"
	defaultAPIEndpoint   = "https://graph.microsoft.com/v1.0"
)

var (
	defaultLoginScopes = []string{"https://graph.microsoft.com/.default"}

	defaultSelectUsers   = []string{"accountEnabled", "userPrincipalName", "mail", "displayName", "givenName", "surname", "jobTitle", "officeLocation", "mobilePhone", "businessPhones"}
	defaultSelectGroups  = []string{"displayName", "members"}
	defaultSelectDevices = []string{"accountEnabled", "deviceId", "displayName", "operatingSystem", "operatingSystemVersion", "physicalIds", "extensionAttributes", "alternativeSecurityIds"}
)

// DefaultConfig returns a Config with sensible defaults matching the
// legacy EntraID provider.
func DefaultConfig() Config {
	return Config{
		LoginEndpoint:  defaultLoginEndpoint,
		LoginScopes:    defaultLoginScopes,
		APIEndpoint:    defaultAPIEndpoint,
		SelectUsers:    defaultSelectUsers,
		SelectGroups:   defaultSelectGroups,
		SelectDevices:  defaultSelectDevices,
		SyncInterval:   24 * time.Hour,
		UpdateInterval: 15 * time.Minute,
	}
}

var (
	errMissingTenantID = errors.New("tenant_id is required")
	errMissingClientID = errors.New("client_id is required")
	errMissingSecret   = errors.New("client_secret is required")
	errInvalidSync     = errors.New("sync_interval must be positive")
	errInvalidUpdate   = errors.New("update_interval must be positive")
	errSyncNotLonger   = errors.New("sync_interval must be greater than update_interval")
	errInvalidDataset  = errors.New("dataset must be 'all', 'users', 'devices' or empty")
	errInvalidEnrich   = errors.New("unknown enrich_with value")
)

var validEnrichments = map[string]bool{
	"mfa":  true,
	"none": true,
}

// Validate returns an error if the Config is invalid.
func (c *Config) Validate() error {
	switch {
	case c.TenantID == "":
		return errMissingTenantID
	case c.ClientID == "":
		return errMissingClientID
	case c.ClientSecret == "":
		return errMissingSecret
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
			return errInvalidEnrich
		}
	}
	return nil
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

func (c *Config) wantMFA() bool {
	for _, e := range c.EnrichWith {
		if strings.EqualFold(e, "mfa") {
			return true
		}
	}
	return false
}

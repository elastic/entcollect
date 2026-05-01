// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package jamf

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/elastic/entcollect"
	"github.com/elastic/entcollect/idset"
)

const (
	keySyncTime   = "jamf.cursor.last_sync"
	keyUpdateTime = "jamf.cursor.last_update"
)

// Provider syncs Jamf computer inventory via the entcollect.Provider interface.
type Provider struct {
	cfg    Config
	client *http.Client
}

var _ entcollect.Provider = (*Provider)(nil)

// New returns a Provider using a default HTTP client.
func New(cfg Config) *Provider {
	return NewWithClient(cfg, &http.Client{Timeout: 30 * time.Second})
}

// NewWithClient returns a Provider using the provided HTTP client. Intended
// for testing or custom transport configuration.
func NewWithClient(cfg Config, client *http.Client) *Provider {
	return &Provider{cfg: cfg, client: client}
}

// FullSync fetches the complete Jamf computer inventory and emits a document
// for each device. It updates the jamf.cursor.last_sync key in store.
func (p *Provider) FullSync(ctx context.Context, store entcollect.Store, pub entcollect.Publisher, log *slog.Logger) error {
	return p.doSync(ctx, store, pub, log, keySyncTime)
}

// IncrementalSync fetches the complete Jamf computer inventory and emits a
// document for each device, updating jamf.cursor.last_update. Because the
// Jamf API has no time-filtered endpoint, this is identical to FullSync.
func (p *Provider) IncrementalSync(ctx context.Context, store entcollect.Store, pub entcollect.Publisher, log *slog.Logger) error {
	return p.doSync(ctx, store, pub, log, keyUpdateTime)
}

func (p *Provider) doSync(ctx context.Context, store entcollect.Store, pub entcollect.Publisher, log *slog.Logger, cursorKey string) error {
	tok, err := GetToken(ctx, p.client, p.cfg.TenantID, p.cfg.Username, p.cfg.Password)
	if err != nil {
		return fmt.Errorf("jamf: get token: %w", err)
	}

	ids := idset.New(p.cfg.IDSetShards)
	if err := ids.Load(store); err != nil {
		return fmt.Errorf("jamf: load idset: %w", err)
	}

	now := time.Now().UTC()
	total := 0
	for page := 0; ; page++ {
		if !tok.valid(p.cfg.TokenGrace) {
			tok, err = GetToken(ctx, p.client, p.cfg.TenantID, p.cfg.Username, p.cfg.Password)
			if err != nil {
				return fmt.Errorf("jamf: refresh token: %w", err)
			}
		}
		computers, err := GetComputers(ctx, p.client, p.cfg.TenantID, tok, page, p.cfg.PageSize)
		if err != nil {
			return fmt.Errorf("jamf: get computers page %d: %w", page, err)
		}

		for _, c := range computers.Results {
			if c.UDID == nil {
				log.Warn("skipping computer with missing UDID", "name", ptrStr(c.Name))
				continue
			}
			udid := *c.UDID
			ids.Add(udid)

			if err := pub(ctx, entcollect.Document{
				ID:        udid,
				Kind:      entcollect.KindDevice,
				Action:    deviceAction(ids, udid, c.IsManaged),
				Timestamp: now,
				Fields:    map[string]any{"jamf": c, "device.id": udid},
			}); err != nil {
				return fmt.Errorf("jamf: publish: %w", err)
			}
		}

		total += len(computers.Results)
		if len(computers.Results) == 0 || total >= computers.TotalCount {
			break
		}
	}

	for _, udid := range ids.Missing() {
		if err := pub(ctx, entcollect.Document{
			ID:        udid,
			Kind:      entcollect.KindDevice,
			Action:    entcollect.ActionDeleted,
			Timestamp: now,
			Fields:    map[string]any{"device.id": udid},
		}); err != nil {
			return fmt.Errorf("jamf: publish deletion: %w", err)
		}
	}

	if err := ids.Save(store); err != nil {
		return fmt.Errorf("jamf: save idset: %w", err)
	}
	if err := store.Set(cursorKey, now); err != nil {
		return fmt.Errorf("jamf: set cursor: %w", err)
	}
	return nil
}

// deviceAction determines the lifecycle action for a device. Unmanaged devices
// (isManaged nil or false) are ActionDeleted. Previously-seen managed devices
// are ActionModified; new ones are ActionDiscovered.
//
// The nil check for isManaged fixes a nil-pointer dereference in the legacy
// beats provider, which used `c.IsManaged != nil` (should be `== nil`).
func deviceAction(ids *idset.Set, udid string, isManaged *bool) entcollect.Action {
	if isManaged == nil || !*isManaged {
		return entcollect.ActionDeleted
	}
	if ids.WasPresent(udid) {
		return entcollect.ActionModified
	}
	return entcollect.ActionDiscovered
}

func ptrStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

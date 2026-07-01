// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package entraid provides an EntraID (Azure AD) identity provider for the
// entcollect library.
//
// The provider syncs users and devices from Microsoft Graph via delta queries.
// Deletion detection is native: the API annotates removed entities with
// @removed, so no idset is needed. Persistent state is two delta URL strings
// (one for users, one for devices).
//
// Transitive group membership is computed from a scratch-backed graph built
// fresh each sync by listing all groups and their members. This avoids
// storing group relationships between syncs but means every active sync
// (one where at least one user or device changed) incurs O(groups + members)
// API calls regardless of batch size. When no users or devices changed,
// the group fetch is skipped entirely.
//
// Group membership changes are invisible to IncrementalSync. The user
// delta endpoint does not report group membership changes — if a user's
// groups change but no user property changes, the user is not in the
// delta results. This is corrected on the next FullSync (default 24h).
// Operators in security-sensitive environments should lower sync_interval.
package entraid

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/elastic/entcollect"
)

const (
	keyCursorUsersDelta   = "entraid.cursor.users_delta"
	keyCursorDevicesDelta = "entraid.cursor.devices_delta"
)

// Provider syncs EntraID identities via the entcollect.Provider interface.
type Provider struct {
	cfg    Config
	client *http.Client
	ts     *tokenSource
}

var _ entcollect.Provider = (*Provider)(nil)

// New returns a Provider with a default HTTP client.
func New(cfg Config) *Provider {
	return NewWithClient(cfg, http.DefaultClient)
}

// NewWithClient returns a Provider using the given HTTP client.
func NewWithClient(cfg Config, client *http.Client) *Provider {
	return &Provider{
		cfg:    cfg,
		client: client,
		ts:     newTokenSource(cfg, client),
	}
}

// FullSync enumerates all entities from EntraID, builds the transitive
// group graph, and emits a document for each entity. Stored delta URLs
// are cleared first so the API returns the full entity set.
func (p *Provider) FullSync(ctx context.Context, store entcollect.Store, pub entcollect.Publisher, log *slog.Logger) error {
	store.Delete(keyCursorUsersDelta)
	store.Delete(keyCursorDevicesDelta)

	gc := p.newGraphClient(log)

	var (
		users    []userEntry
		devices  []deviceEntry
		userDL   string
		deviceDL string
	)

	if p.cfg.wantUsers() {
		var err error
		users, userDL, err = gc.getUsers(ctx, "", p.cfg.SelectUsers)
		if err != nil {
			return fmt.Errorf("entraid: full sync users: %w", err)
		}
		log.Info("fetched users", "count", len(users))
	}

	if p.cfg.wantDevices() {
		var err error
		devices, deviceDL, err = gc.getDevices(ctx, "", p.cfg.SelectDevices)
		if err != nil {
			return fmt.Errorf("entraid: full sync devices: %w", err)
		}
		log.Info("fetched devices", "count", len(devices))
	}

	mg, err := p.buildGraph(ctx, gc)
	if err != nil {
		return fmt.Errorf("entraid: build membership graph: %w", err)
	}
	defer mg.close()

	var mfa map[string]*MFADetails
	if p.cfg.wantMFA() && len(users) > 0 {
		mfa, err = gc.getMFADetails(ctx)
		if err != nil {
			log.Warn("MFA enrichment failed, continuing without MFA data", "error", err)
		}
	}

	var signIn map[string]*SignInActivityDetails
	if p.cfg.wantSignInActivity() && len(users) > 0 {
		signIn, err = gc.getSignInActivity(ctx)
		if err != nil {
			log.Warn("sign-in activity enrichment failed, continuing without sign-in data", "error", err)
		}
	}

	now := time.Now().UTC()

	for _, u := range users {
		if u.id == "" {
			continue
		}
		action := entcollect.ActionDiscovered
		if u.removed {
			action = entcollect.ActionDeleted
		}
		fields := map[string]any{
			"azure_ad": u.Fields,
			"user.id":  u.id,
		}
		if groups, err := userTransitiveGroups(mg, u.id); err != nil {
			return fmt.Errorf("entraid: transitive groups for user %s: %w", u.id, err)
		} else if len(groups) > 0 {
			fields["user.group"] = groups
		}
		if mfa != nil {
			if m, ok := mfa[u.id]; ok {
				fields["user.risk.mfa"] = m
			}
		}
		if signIn != nil {
			if s, ok := signIn[u.id]; ok {
				fields["azure_ad.signInActivity"] = s
			}
		}
		if err := pub(ctx, entcollect.Document{
			ID:        u.id,
			Kind:      entcollect.KindUser,
			Action:    action,
			Timestamp: now,
			Fields:    fields,
		}); err != nil {
			return fmt.Errorf("entraid: publish user %s: %w", u.id, err)
		}
	}

	for _, d := range devices {
		if d.id == "" {
			continue
		}
		action := entcollect.ActionDiscovered
		if d.removed {
			action = entcollect.ActionDeleted
		}
		fields := map[string]any{
			"azure_ad":  d.Fields,
			"device.id": d.id,
		}
		if groups, err := deviceTransitiveGroups(mg, d.id); err != nil {
			return fmt.Errorf("entraid: transitive groups for device %s: %w", d.id, err)
		} else if len(groups) > 0 {
			fields["device.group"] = groups
		}
		if err := p.enrichDeviceOwnership(ctx, gc, d.id, fields); err != nil {
			log.Warn("device ownership enrichment failed", "device", d.id, "error", err)
		}
		if err := pub(ctx, entcollect.Document{
			ID:        d.id,
			Kind:      entcollect.KindDevice,
			Action:    action,
			Timestamp: now,
			Fields:    fields,
		}); err != nil {
			return fmt.Errorf("entraid: publish device %s: %w", d.id, err)
		}
	}

	if userDL != "" {
		if err := store.Set(keyCursorUsersDelta, userDL); err != nil {
			return fmt.Errorf("entraid: store user delta link: %w", err)
		}
	}
	if deviceDL != "" {
		if err := store.Set(keyCursorDevicesDelta, deviceDL); err != nil {
			return fmt.Errorf("entraid: store device delta link: %w", err)
		}
	}

	return nil
}

// IncrementalSync fetches only entities changed since the last sync
// using stored delta links. If no entities changed, the group fetch
// is skipped entirely.
func (p *Provider) IncrementalSync(ctx context.Context, store entcollect.Store, pub entcollect.Publisher, log *slog.Logger) error {
	gc := p.newGraphClient(log)

	var (
		users    []userEntry
		devices  []deviceEntry
		userDL   string
		deviceDL string
	)

	if p.cfg.wantUsers() {
		storedDL, err := loadDeltaLink(store, keyCursorUsersDelta)
		if err != nil {
			return err
		}
		users, userDL, err = gc.getUsers(ctx, storedDL, p.cfg.SelectUsers)
		if errors.Is(err, ErrDeltaExpired) {
			log.Warn("user delta link expired, falling back to full fetch")
			store.Delete(keyCursorUsersDelta)
			users, userDL, err = gc.getUsers(ctx, "", p.cfg.SelectUsers)
		}
		if err != nil {
			return fmt.Errorf("entraid: incremental sync users: %w", err)
		}
		log.Info("fetched user delta", "count", len(users))
	}

	if p.cfg.wantDevices() {
		storedDL, err := loadDeltaLink(store, keyCursorDevicesDelta)
		if err != nil {
			return err
		}
		devices, deviceDL, err = gc.getDevices(ctx, storedDL, p.cfg.SelectDevices)
		if errors.Is(err, ErrDeltaExpired) {
			log.Warn("device delta link expired, falling back to full fetch")
			store.Delete(keyCursorDevicesDelta)
			devices, deviceDL, err = gc.getDevices(ctx, "", p.cfg.SelectDevices)
		}
		if err != nil {
			return fmt.Errorf("entraid: incremental sync devices: %w", err)
		}
		log.Info("fetched device delta", "count", len(devices))
	}

	if len(users) == 0 && len(devices) == 0 {
		if userDL != "" {
			if err := store.Set(keyCursorUsersDelta, userDL); err != nil {
				return fmt.Errorf("entraid: store user delta link: %w", err)
			}
		}
		if deviceDL != "" {
			if err := store.Set(keyCursorDevicesDelta, deviceDL); err != nil {
				return fmt.Errorf("entraid: store device delta link: %w", err)
			}
		}
		log.Info("no changes detected, skipping group fetch")
		return nil
	}

	mg, err := p.buildGraph(ctx, gc)
	if err != nil {
		return fmt.Errorf("entraid: build membership graph: %w", err)
	}
	defer mg.close()

	var mfa map[string]*MFADetails
	if p.cfg.wantMFA() && len(users) > 0 {
		mfa, err = gc.getMFADetails(ctx)
		if err != nil {
			log.Warn("MFA enrichment failed, continuing without MFA data", "error", err)
		}
	}

	var signIn map[string]*SignInActivityDetails
	if p.cfg.wantSignInActivity() && len(users) > 0 {
		signIn, err = gc.getSignInActivity(ctx)
		if err != nil {
			log.Warn("sign-in activity enrichment failed, continuing without sign-in data", "error", err)
		}
	}

	now := time.Now().UTC()

	for _, u := range users {
		if u.id == "" {
			continue
		}
		action := entcollect.ActionModified
		if u.removed {
			action = entcollect.ActionDeleted
		}
		fields := map[string]any{
			"azure_ad": u.Fields,
			"user.id":  u.id,
		}
		if groups, err := userTransitiveGroups(mg, u.id); err != nil {
			return fmt.Errorf("entraid: transitive groups for user %s: %w", u.id, err)
		} else if len(groups) > 0 {
			fields["user.group"] = groups
		}
		if mfa != nil {
			if m, ok := mfa[u.id]; ok {
				fields["user.risk.mfa"] = m
			}
		}
		if signIn != nil {
			if s, ok := signIn[u.id]; ok {
				fields["azure_ad.signInActivity"] = s
			}
		}
		if err := pub(ctx, entcollect.Document{
			ID:        u.id,
			Kind:      entcollect.KindUser,
			Action:    action,
			Timestamp: now,
			Fields:    fields,
		}); err != nil {
			return fmt.Errorf("entraid: publish user %s: %w", u.id, err)
		}
	}

	for _, d := range devices {
		if d.id == "" {
			continue
		}
		action := entcollect.ActionModified
		if d.removed {
			action = entcollect.ActionDeleted
		}
		fields := map[string]any{
			"azure_ad":  d.Fields,
			"device.id": d.id,
		}
		if groups, err := deviceTransitiveGroups(mg, d.id); err != nil {
			return fmt.Errorf("entraid: transitive groups for device %s: %w", d.id, err)
		} else if len(groups) > 0 {
			fields["device.group"] = groups
		}
		if err := p.enrichDeviceOwnership(ctx, gc, d.id, fields); err != nil {
			log.Warn("device ownership enrichment failed", "device", d.id, "error", err)
		}
		if err := pub(ctx, entcollect.Document{
			ID:        d.id,
			Kind:      entcollect.KindDevice,
			Action:    action,
			Timestamp: now,
			Fields:    fields,
		}); err != nil {
			return fmt.Errorf("entraid: publish device %s: %w", d.id, err)
		}
	}

	if userDL != "" {
		if err := store.Set(keyCursorUsersDelta, userDL); err != nil {
			return fmt.Errorf("entraid: store user delta link: %w", err)
		}
	}
	if deviceDL != "" {
		if err := store.Set(keyCursorDevicesDelta, deviceDL); err != nil {
			return fmt.Errorf("entraid: store device delta link: %w", err)
		}
	}

	return nil
}

func (p *Provider) newGraphClient(log *slog.Logger) *graphClient {
	return &graphClient{
		baseURL:    p.cfg.APIEndpoint,
		token:      p.ts.Token,
		resetToken: p.ts.Reset,
		client:     p.client,
		log:        log,
	}
}

func (p *Provider) buildGraph(ctx context.Context, gc *graphClient) (membershipGraph, error) {
	groups, err := gc.getGroups(ctx, p.cfg.SelectGroups)
	if err != nil {
		return nil, err
	}

	mg, err := newScratchBackend(p.cfg.ScratchDir)
	if err != nil {
		return nil, fmt.Errorf("open scratch storage: %w", err)
	}

	for _, g := range groups {
		if err := mg.addGroup(g); err != nil {
			mg.close()
			return nil, fmt.Errorf("add group %s: %w", g.ID, err)
		}
		members, err := gc.getGroupMembers(ctx, g.ID)
		if err != nil {
			mg.close()
			return nil, fmt.Errorf("members for group %s: %w", g.ID, err)
		}
		if err := mg.addMembers(g.ID, members); err != nil {
			mg.close()
			return nil, fmt.Errorf("add members for group %s: %w", g.ID, err)
		}
	}
	return mg, nil
}

func (p *Provider) enrichDeviceOwnership(ctx context.Context, gc *graphClient, deviceID string, fields map[string]any) error {
	owners, err := gc.getDeviceRegistered(ctx, deviceID, "registeredOwners")
	if err != nil {
		return fmt.Errorf("registered owners: %w", err)
	}
	if len(owners) > 0 {
		fields["device.registered_owners"] = owners
	}

	users, err := gc.getDeviceRegistered(ctx, deviceID, "registeredUsers")
	if err != nil {
		return fmt.Errorf("registered users: %w", err)
	}
	if len(users) > 0 {
		fields["device.registered_users"] = users
	}

	return nil
}

func loadDeltaLink(store entcollect.Store, key string) (string, error) {
	var dl string
	err := store.Get(key, &dl)
	if errors.Is(err, entcollect.ErrKeyNotFound) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("entraid: load %s: %w", key, err)
	}
	return dl, nil
}

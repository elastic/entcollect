// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package okta provides an Okta identity provider for the entcollect library.
//
// The provider syncs users and devices from an Okta domain via the REST API.
// FullSync performs exhaustive enumeration with idset-based deletion detection
// and bulk-fetch group enrichment (O(groups) rather than O(users)).
// IncrementalSync fetches only entities changed since the last sync using the
// lastUpdated filter, with per-user group enrichment for the changed batch.
//
// Deletion detection is full-sync-only. Between full syncs (default 24h),
// entities removed from Okta produce no ActionDeleted event. Users with
// DEPROVISIONED status are published as normal entities — they are not treated
// as deletions. Idset deletion detects users truly purged from the API.
//
// Supervises enrichment is computed from profile.managerId across the current
// batch. On full sync this is complete. On incremental sync it only covers
// users in the batch — managers outside the batch whose reports changed won't
// be re-emitted until the next full sync.
package okta

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/elastic/entcollect"
	"github.com/elastic/entcollect/idset"
)

const (
	keyCursorLastSync   = "okta.cursor.last_sync"
	keyCursorLastUpdate = "okta.cursor.last_update"
)

// Provider syncs Okta identities via the entcollect.Provider interface.
type Provider struct {
	cfg    Config
	client *http.Client
}

var _ entcollect.Provider = (*Provider)(nil)

// New returns a Provider with a default HTTP client.
func New(cfg Config) *Provider {
	return &Provider{cfg: cfg, client: http.DefaultClient}
}

// NewWithClient returns a Provider using the given HTTP client as the
// base transport. For OAuth2, the OAuth2 transport wraps this client.
func NewWithClient(cfg Config, client *http.Client) *Provider {
	return &Provider{cfg: cfg, client: client}
}

// FullSync enumerates all entities from Okta, emits a document for each,
// and detects deletions via idsets.
func (p *Provider) FullSync(ctx context.Context, store entcollect.Store, pub entcollect.Publisher, log *slog.Logger) error {
	cli, key, err := p.authClient(ctx)
	if err != nil {
		return fmt.Errorf("okta: auth: %w", err)
	}
	lim := NewRateLimiter(p.cfg.LimitWindow, p.cfg.LimitFixed)
	now := time.Now().UTC()
	enrich := p.cfg.enrichmentSet()
	var latestLastUpdated time.Time

	if p.cfg.wantUsers() {
		users := idset.New(p.cfg.IDSetShards, idset.WithPrefix("okta.users."))
		if err := users.Load(store); err != nil {
			return fmt.Errorf("okta: load users idset: %w", err)
		}

		allUsers, latest, err := p.fetchAllUsers(ctx, cli, key, lim, log)
		if err != nil {
			return err
		}
		if latest.After(latestLastUpdated) {
			latestLastUpdated = latest
		}

		var groupMapping map[string][]Group
		if enrich["groups"] {
			groupMapping, err = p.bulkFetchGroupMapping(ctx, cli, key, lim, log)
			if err != nil {
				return err
			}
		}

		var supervisesMapping map[string][]SupervisedUser
		if enrich["supervises"] {
			supervisesMapping = buildSupervisesMap(allUsers)
		}

		permCache := make(map[string][]Permission)
		for _, u := range allUsers {
			users.Add(u.ID)

			action := entcollect.ActionDiscovered
			if users.WasPresent(u.ID) {
				action = entcollect.ActionModified
			}

			fields := map[string]any{
				"okta":    u,
				"user.id": u.ID,
			}
			if groupMapping != nil {
				fields["groups"] = groupMapping[u.ID]
			}
			if supervisesMapping != nil {
				if subs := supervisesMapping[u.ID]; subs != nil {
					fields["supervises"] = subs
				}
			}
			if err := p.enrichUser(ctx, cli, key, lim, log, enrich, permCache, &u, fields); err != nil {
				return err
			}

			if err := pub(ctx, entcollect.Document{
				ID:        u.ID,
				Kind:      entcollect.KindUser,
				Action:    action,
				Timestamp: now,
				Fields:    fields,
			}); err != nil {
				return fmt.Errorf("okta: publish user: %w", err)
			}
		}

		for _, id := range users.Missing() {
			if err := pub(ctx, entcollect.Document{
				ID:        id,
				Kind:      entcollect.KindUser,
				Action:    entcollect.ActionDeleted,
				Timestamp: now,
				Fields:    map[string]any{"user.id": id},
			}); err != nil {
				return fmt.Errorf("okta: publish user deletion: %w", err)
			}
		}

		if err := users.Save(store); err != nil {
			return fmt.Errorf("okta: save users idset: %w", err)
		}
	}

	if p.cfg.wantDevices() {
		devices := idset.New(p.cfg.IDSetShards, idset.WithPrefix("okta.devices."))
		if err := devices.Load(store); err != nil {
			return fmt.Errorf("okta: load devices idset: %w", err)
		}

		allDevices, err := p.fetchAllDevices(ctx, cli, key, lim, log)
		if err != nil {
			return err
		}

		for i := range allDevices {
			d := &allDevices[i]
			devices.Add(d.ID)

			devUsers, _, err := GetDeviceUsers(ctx, cli, p.cfg.Domain, key, d.ID, nil, OmitNone, lim, log)
			if err != nil {
				return fmt.Errorf("okta: get device users for %s: %w", d.ID, err)
			}
			d.Users = devUsers

			action := entcollect.ActionDiscovered
			if devices.WasPresent(d.ID) {
				action = entcollect.ActionModified
			}

			if err := pub(ctx, entcollect.Document{
				ID:        d.ID,
				Kind:      entcollect.KindDevice,
				Action:    action,
				Timestamp: now,
				Fields:    map[string]any{"okta": d, "device.id": d.ID},
			}); err != nil {
				return fmt.Errorf("okta: publish device: %w", err)
			}
		}

		for _, id := range devices.Missing() {
			if err := pub(ctx, entcollect.Document{
				ID:        id,
				Kind:      entcollect.KindDevice,
				Action:    entcollect.ActionDeleted,
				Timestamp: now,
				Fields:    map[string]any{"device.id": id},
			}); err != nil {
				return fmt.Errorf("okta: publish device deletion: %w", err)
			}
		}

		if err := devices.Save(store); err != nil {
			return fmt.Errorf("okta: save devices idset: %w", err)
		}
	}

	if !latestLastUpdated.IsZero() {
		if err := store.Set(keyCursorLastSync, latestLastUpdated); err != nil {
			return fmt.Errorf("okta: set cursor: %w", err)
		}
	}
	return nil
}

// IncrementalSync fetches only entities changed since the last sync. Idsets
// are not touched — incremental sync cannot distinguish "unchanged" from
// "deleted", so running the idset would cause false deletions on the next
// full sync.
func (p *Provider) IncrementalSync(ctx context.Context, store entcollect.Store, pub entcollect.Publisher, log *slog.Logger) error {
	var since time.Time
	err := store.Get(keyCursorLastUpdate, &since)
	if err != nil && !isKeyNotFound(err) {
		return fmt.Errorf("okta: get cursor: %w", err)
	}
	if since.IsZero() {
		// Fall back to last_sync if last_update hasn't been written yet
		// (first incremental after a full sync).
		err = store.Get(keyCursorLastSync, &since)
		if err != nil && !isKeyNotFound(err) {
			return fmt.Errorf("okta: get cursor: %w", err)
		}
	}

	cli, key, err := p.authClient(ctx)
	if err != nil {
		return fmt.Errorf("okta: auth: %w", err)
	}
	lim := NewRateLimiter(p.cfg.LimitWindow, p.cfg.LimitFixed)
	now := time.Now().UTC()
	enrich := p.cfg.enrichmentSet()
	var latestLastUpdated time.Time

	if p.cfg.wantUsers() {
		query := url.Values{}
		if !since.IsZero() {
			query.Set("search", fmt.Sprintf(`lastUpdated ge "%s" and status pr`, since.Format(ISO8601)))
		} else {
			query.Set("search", "status pr")
		}

		users, latest, err := p.paginateUsers(ctx, cli, key, query, lim, log)
		if err != nil {
			return err
		}
		if latest.After(latestLastUpdated) {
			latestLastUpdated = latest
		}

		var supervisesMapping map[string][]SupervisedUser
		if enrich["supervises"] {
			supervisesMapping = buildSupervisesMap(users)
		}

		permCache := make(map[string][]Permission)
		for _, u := range users {
			fields := map[string]any{
				"okta":    u,
				"user.id": u.ID,
			}

			if enrich["groups"] {
				groups, _, err := GetUserGroups(ctx, cli, p.cfg.Domain, key, u.ID, lim, log)
				if err != nil {
					return fmt.Errorf("okta: get groups for user %s: %w", u.ID, err)
				}
				fields["groups"] = groups
			}
			if supervisesMapping != nil {
				if subs := supervisesMapping[u.ID]; subs != nil {
					fields["supervises"] = subs
				}
			}
			if err := p.enrichUser(ctx, cli, key, lim, log, enrich, permCache, &u, fields); err != nil {
				return err
			}

			if err := pub(ctx, entcollect.Document{
				ID:        u.ID,
				Kind:      entcollect.KindUser,
				Action:    entcollect.ActionModified,
				Timestamp: now,
				Fields:    fields,
			}); err != nil {
				return fmt.Errorf("okta: publish user: %w", err)
			}
		}
	}

	if p.cfg.wantDevices() {
		query := url.Values{}
		if !since.IsZero() {
			query.Set("search", fmt.Sprintf(`lastUpdated ge "%s" and status pr`, since.Format(ISO8601)))
		}

		devices, err := p.paginateDevices(ctx, cli, key, query, lim, log)
		if err != nil {
			return err
		}

		for i := range devices {
			d := &devices[i]
			devUsers, _, err := GetDeviceUsers(ctx, cli, p.cfg.Domain, key, d.ID, nil, OmitNone, lim, log)
			if err != nil {
				return fmt.Errorf("okta: get device users for %s: %w", d.ID, err)
			}
			d.Users = devUsers

			if err := pub(ctx, entcollect.Document{
				ID:        d.ID,
				Kind:      entcollect.KindDevice,
				Action:    entcollect.ActionModified,
				Timestamp: now,
				Fields:    map[string]any{"okta": d, "device.id": d.ID},
			}); err != nil {
				return fmt.Errorf("okta: publish device: %w", err)
			}
		}
	}

	if !latestLastUpdated.IsZero() {
		if err := store.Set(keyCursorLastUpdate, latestLastUpdated); err != nil {
			return fmt.Errorf("okta: set cursor: %w", err)
		}
	}
	return nil
}

// authClient returns an HTTP client and API key for requests. For token
// auth, the base client is returned with the token. For OAuth2, a new
// client with an OAuth2 transport is returned (key is empty since the
// transport sets Authorization).
func (p *Provider) authClient(ctx context.Context) (*http.Client, string, error) {
	if p.cfg.Token != "" {
		return p.client, p.cfg.Token, nil
	}
	if p.cfg.OAuth2 != nil {
		cli, err := newOAuth2Client(ctx, p.client, *p.cfg.OAuth2)
		if err != nil {
			return nil, "", err
		}
		return cli, "", nil
	}
	return nil, "", errors.New("no auth configured")
}

// fetchAllUsers retrieves all users from Okta with search=status pr to
// include all statuses. Returns all users and the latest lastUpdated.
func (p *Provider) fetchAllUsers(ctx context.Context, cli *http.Client, key string, lim *RateLimiter, log *slog.Logger) ([]User, time.Time, error) {
	query := url.Values{"search": {"status pr"}}
	if p.cfg.BatchSize > 0 {
		query.Set("limit", fmt.Sprint(p.cfg.BatchSize))
	}
	return p.paginateUsers(ctx, cli, key, query, lim, log)
}

// paginateUsers fetches users with pagination, tracking the latest lastUpdated.
func (p *Provider) paginateUsers(ctx context.Context, cli *http.Client, key string, query url.Values, lim *RateLimiter, log *slog.Logger) ([]User, time.Time, error) {
	omit := OmitCredentials | OmitCredentialsLinks | OmitTransitioningToStatus
	var all []User
	var latest time.Time

	for {
		batch, headers, err := GetUsers(ctx, cli, p.cfg.Domain, key, query, omit, lim, log)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("okta: get users: %w", err)
		}
		for _, u := range batch {
			if u.LastUpdated.After(latest) {
				latest = u.LastUpdated
			}
		}
		all = append(all, batch...)
		log.Info("received users from API", "count", len(batch), "total", len(all))

		query, err = Next(headers)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("okta: parse pagination: %w", err)
		}
	}
	return all, latest, nil
}

// bulkFetchGroupMapping fetches all groups and their members, returning
// a map from user ID to the groups that user belongs to. This is O(groups)
// rather than O(users).
func (p *Provider) bulkFetchGroupMapping(ctx context.Context, cli *http.Client, key string, lim *RateLimiter, log *slog.Logger) (map[string][]Group, error) {
	allGroups, err := p.paginateGroups(ctx, cli, key, lim, log)
	if err != nil {
		return nil, err
	}

	mapping := make(map[string][]Group)
	for _, g := range allGroups {
		members, err := p.paginateGroupMembers(ctx, cli, key, g.ID, lim, log)
		if err != nil {
			return nil, err
		}
		for _, m := range members {
			mapping[m.ID] = append(mapping[m.ID], g)
		}
	}
	log.Info("built bulk group mapping", "groups", len(allGroups), "user_mappings", len(mapping))
	return mapping, nil
}

func (p *Provider) paginateGroups(ctx context.Context, cli *http.Client, key string, lim *RateLimiter, log *slog.Logger) ([]Group, error) {
	query := url.Values{}
	if p.cfg.BatchSize > 0 {
		query.Set("limit", fmt.Sprint(p.cfg.BatchSize))
	}
	var all []Group
	for {
		batch, headers, err := GetGroups(ctx, cli, p.cfg.Domain, key, query, lim, log)
		if err != nil {
			return nil, fmt.Errorf("okta: get groups: %w", err)
		}
		all = append(all, batch...)

		query, err = Next(headers)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("okta: parse group pagination: %w", err)
		}
	}
	log.Info("received groups from API", "count", len(all))
	return all, nil
}

func (p *Provider) paginateGroupMembers(ctx context.Context, cli *http.Client, key, groupID string, lim *RateLimiter, log *slog.Logger) ([]User, error) {
	var all []User
	query := url.Values{}
	for {
		batch, headers, err := GetGroupMembers(ctx, cli, p.cfg.Domain, key, groupID, query, lim, log)
		if err != nil {
			return nil, fmt.Errorf("okta: get group %s members: %w", groupID, err)
		}
		all = append(all, batch...)

		query, err = Next(headers)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("okta: parse group member pagination: %w", err)
		}
	}
	return all, nil
}

// fetchAllDevices retrieves all devices from Okta.
func (p *Provider) fetchAllDevices(ctx context.Context, cli *http.Client, key string, lim *RateLimiter, log *slog.Logger) ([]Device, error) {
	return p.paginateDevices(ctx, cli, key, nil, lim, log)
}

func (p *Provider) paginateDevices(ctx context.Context, cli *http.Client, key string, query url.Values, lim *RateLimiter, log *slog.Logger) ([]Device, error) {
	if query == nil {
		query = url.Values{}
	}
	var all []Device
	for {
		batch, headers, err := GetDevices(ctx, cli, p.cfg.Domain, key, query, lim, log)
		if err != nil {
			return nil, fmt.Errorf("okta: get devices: %w", err)
		}
		all = append(all, batch...)

		query, err = Next(headers)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("okta: parse device pagination: %w", err)
		}
	}
	log.Info("received devices from API", "count", len(all))
	return all, nil
}

// enrichUser adds optional per-user enrichment to fields.
func (p *Provider) enrichUser(ctx context.Context, cli *http.Client, key string, lim *RateLimiter, log *slog.Logger, enrich map[string]bool, permCache map[string][]Permission, u *User, fields map[string]any) error {
	if enrich["factors"] {
		factors, _, err := GetUserFactors(ctx, cli, p.cfg.Domain, key, u.ID, lim, log)
		if err != nil {
			return fmt.Errorf("okta: get factors for user %s: %w", u.ID, err)
		}
		fields["factors"] = factors
	}
	if enrich["roles"] {
		roles, _, err := GetUserRoles(ctx, cli, p.cfg.Domain, key, u.ID, lim, log)
		if err != nil {
			return fmt.Errorf("okta: get roles for user %s: %w", u.ID, err)
		}
		if enrich["permissions"] {
			for i := range roles {
				roleID := roles[i].RoleID
				if roleID == "" {
					roleID = roles[i].ID
				}
				if cached, ok := permCache[roleID]; ok {
					roles[i].Permissions = cached
					continue
				}
				perms, _, err := GetRolePermissions(ctx, cli, p.cfg.Domain, key, roleID, lim, log)
				if err != nil {
					return fmt.Errorf("okta: get permissions for role %s: %w", roleID, err)
				}
				permCache[roleID] = perms
				roles[i].Permissions = perms
			}
		}
		fields["roles"] = roles
	}
	if enrich["devices"] {
		devs, _, err := GetUserDevices(ctx, cli, p.cfg.Domain, key, u.ID, lim, log)
		if err != nil {
			return fmt.Errorf("okta: get devices for user %s: %w", u.ID, err)
		}
		fields["devices"] = devs
	}
	return nil
}

// buildSupervisesMap builds a map from manager user ID to the users they
// manage, based on profile.managerId. Only users in the given slice
// contribute — managers outside the set won't appear.
func buildSupervisesMap(users []User) map[string][]SupervisedUser {
	m := make(map[string][]SupervisedUser)
	for _, u := range users {
		if u.Profile == nil {
			continue
		}
		managerID, _ := u.Profile["managerId"].(string)
		if managerID == "" {
			continue
		}
		email, _ := u.Profile["email"].(string)
		login, _ := u.Profile["login"].(string)
		m[managerID] = append(m[managerID], SupervisedUser{
			ID:       u.ID,
			Email:    email,
			Username: login,
		})
	}
	return m
}

func isKeyNotFound(err error) bool {
	return errors.Is(err, entcollect.ErrKeyNotFound)
}

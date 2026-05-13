// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package ad provides an Active Directory identity provider for the
// entcollect library.
//
// The provider syncs users, devices (computers), and optionally empty
// groups from an Active Directory domain via LDAP. FullSync performs
// exhaustive enumeration with idset-based deletion detection;
// IncrementalSync fetches only entities changed since the last sync
// (via the whenChanged LDAP attribute) and does not touch idsets.
package ad

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/elastic/entcollect"
	"github.com/elastic/entcollect/idset"
)

const (
	keyCursorWhenChanged = "ad.cursor.when_changed"
)

// Provider syncs Active Directory identities via the entcollect.Provider
// interface.
type Provider struct {
	cfg    Config
	baseDN *ldap.DN
}

var _ entcollect.Provider = (*Provider)(nil)

// New returns a Provider. The Config must have been validated.
func New(cfg Config) (*Provider, error) {
	base, err := ldap.ParseDN(cfg.BaseDN)
	if err != nil {
		return nil, fmt.Errorf("ad: parse base DN: %w", err)
	}
	cfg.UserAttrs = withMandatory(cfg.UserAttrs, "distinguishedName", "whenChanged")
	cfg.GrpAttrs = withMandatory(cfg.GrpAttrs, "distinguishedName", "whenChanged")
	return &Provider{cfg: cfg, baseDN: base}, nil
}

// FullSync enumerates all entities from Active Directory, emits a
// document for each, and detects deletions via idsets. The
// whenChanged cursor is reset to zero (full sync ignores it).
func (p *Provider) FullSync(ctx context.Context, store entcollect.Store, pub entcollect.Publisher, log *slog.Logger) error {
	now := time.Now().UTC()
	var latestWhenChanged time.Time

	if p.cfg.wantUsers() {
		users := idset.New(p.cfg.IDSetShards, idset.WithPrefix("ad.users."))
		if err := users.Load(store); err != nil {
			return fmt.Errorf("ad: load users idset: %w", err)
		}
		wc, err := p.syncEntities(ctx, pub, log, users, "user", now, time.Time{})
		if err != nil {
			return err
		}
		if wc.After(latestWhenChanged) {
			latestWhenChanged = wc
		}
		if err := p.emitDeletions(ctx, pub, users, entcollect.KindUser, "user.id", now); err != nil {
			return err
		}
		if err := users.Save(store); err != nil {
			return fmt.Errorf("ad: save users idset: %w", err)
		}
	}

	if p.cfg.wantDevices() {
		devices := idset.New(p.cfg.IDSetShards, idset.WithPrefix("ad.devices."))
		if err := devices.Load(store); err != nil {
			return fmt.Errorf("ad: load devices idset: %w", err)
		}
		wc, err := p.syncEntities(ctx, pub, log, devices, "device", now, time.Time{})
		if err != nil {
			return err
		}
		if wc.After(latestWhenChanged) {
			latestWhenChanged = wc
		}
		if err := p.emitDeletions(ctx, pub, devices, entcollect.KindDevice, "device.id", now); err != nil {
			return err
		}
		if err := devices.Save(store); err != nil {
			return fmt.Errorf("ad: save devices idset: %w", err)
		}
	}

	if p.cfg.IncludeEmptyGroups {
		groups := idset.New(p.cfg.IDSetShards, idset.WithPrefix("ad.groups."))
		if err := groups.Load(store); err != nil {
			return fmt.Errorf("ad: load groups idset: %w", err)
		}
		wc, err := p.syncEmptyGroups(ctx, pub, log, groups, now, time.Time{})
		if err != nil {
			return err
		}
		if wc.After(latestWhenChanged) {
			latestWhenChanged = wc
		}
		if err := p.emitDeletions(ctx, pub, groups, entcollect.KindGroup, "group.id", now); err != nil {
			return err
		}
		if err := groups.Save(store); err != nil {
			return fmt.Errorf("ad: save groups idset: %w", err)
		}
	}
	if !latestWhenChanged.IsZero() {
		if err := store.Set(keyCursorWhenChanged, latestWhenChanged); err != nil {
			return fmt.Errorf("ad: set cursor: %w", err)
		}
	}
	return nil
}

// IncrementalSync fetches only entities changed since the last sync.
// Idsets are not loaded, updated, or saved: incremental sync has no
// way to distinguish "not returned because unchanged" from "deleted",
// so running the idset would cause false deletions on the next full sync.
func (p *Provider) IncrementalSync(ctx context.Context, store entcollect.Store, pub entcollect.Publisher, log *slog.Logger) error {
	var since time.Time
	err := store.Get(keyCursorWhenChanged, &since)
	if err != nil && !isKeyNotFound(err) {
		return fmt.Errorf("ad: get cursor: %w", err)
	}

	now := time.Now().UTC()
	var latestWhenChanged time.Time

	if p.cfg.wantUsers() {
		wc, err := p.syncEntities(ctx, pub, log, nil, "user", now, since)
		if err != nil {
			return err
		}
		if wc.After(latestWhenChanged) {
			latestWhenChanged = wc
		}
	}

	if p.cfg.wantDevices() {
		wc, err := p.syncEntities(ctx, pub, log, nil, "device", now, since)
		if err != nil {
			return err
		}
		if wc.After(latestWhenChanged) {
			latestWhenChanged = wc
		}
	}

	if p.cfg.IncludeEmptyGroups {
		wc, err := p.syncEmptyGroups(ctx, pub, log, nil, now, since)
		if err != nil {
			return err
		}
		if wc.After(latestWhenChanged) {
			latestWhenChanged = wc
		}
	}

	if !latestWhenChanged.IsZero() {
		if err := store.Set(keyCursorWhenChanged, latestWhenChanged); err != nil {
			return fmt.Errorf("ad: set cursor: %w", err)
		}
	}
	return nil
}

// syncEntities fetches users or devices (controlled by entTyp) from AD
// and publishes a document for each. If ids is non-nil, entity IDs are
// added to it for deletion detection. Returns the latest whenChanged
// timestamp seen.
func (p *Provider) syncEntities(ctx context.Context, pub entcollect.Publisher, log *slog.Logger, ids *idset.Set, entTyp string, now, since time.Time) (time.Time, error) {
	query, kind, idField := p.entityParams(entTyp)
	entries, err := GetDetails(query, p.cfg.URL, p.cfg.User, p.cfg.Password, p.baseDN, since, p.cfg.UserAttrs, p.cfg.GrpAttrs, p.cfg.PagingSize, nil, p.cfg.TLS, entTyp)
	if err != nil {
		return time.Time{}, fmt.Errorf("ad: get %s details: %w", entTyp, err)
	}
	log.Info("received entities from API", "type", entTyp, "count", len(entries))

	var latestWC time.Time
	for _, e := range entries {
		if ids != nil {
			ids.Add(e.ID)
		}

		action := entcollect.ActionDiscovered
		if ids != nil && ids.WasPresent(e.ID) {
			action = entcollect.ActionModified
		}

		err := pub(ctx, entcollect.Document{
			ID:        e.ID,
			Kind:      kind,
			Action:    action,
			Timestamp: now,
			Fields:    map[string]any{"activedirectory": e, idField: e.ID},
		})
		if err != nil {
			return time.Time{}, fmt.Errorf("ad: publish %s: %w", entTyp, err)
		}
		if e.WhenChanged.After(latestWC) {
			latestWC = e.WhenChanged
		}
	}
	return latestWC, nil
}

func (p *Provider) entityParams(entTyp string) (query string, kind entcollect.EntityKind, idField string) {
	switch entTyp {
	case "user":
		query = "(&(objectCategory=person)(objectClass=user))"
		if p.cfg.UserQuery != "" {
			query = p.cfg.UserQuery
		}
		return query, entcollect.KindUser, "user.id"
	case "device":
		query = "(&(objectClass=computer)(objectClass=user))"
		if p.cfg.DeviceQuery != "" {
			query = p.cfg.DeviceQuery
		}
		return query, entcollect.KindDevice, "device.id"
	default:
		panic("unreachable: invalid entTyp " + entTyp)
	}
}

// syncEmptyGroups fetches groups with no direct members and publishes a
// document for each. If ids is non-nil, group IDs are added. Returns the
// latest whenChanged timestamp seen.
func (p *Provider) syncEmptyGroups(ctx context.Context, pub entcollect.Publisher, log *slog.Logger, ids *idset.Set, now, since time.Time) (time.Time, error) {
	entries, err := GetEmptyGroups(p.cfg.URL, p.cfg.User, p.cfg.Password, p.baseDN, since, p.cfg.GrpAttrs, p.cfg.PagingSize, nil, p.cfg.TLS)
	if err != nil {
		return time.Time{}, fmt.Errorf("ad: get empty groups: %w", err)
	}
	log.Info("received empty groups from API", "count", len(entries))

	var latestWC time.Time
	for _, e := range entries {
		if ids != nil {
			ids.Add(e.ID)
		}

		action := entcollect.ActionDiscovered
		if ids != nil && ids.WasPresent(e.ID) {
			action = entcollect.ActionModified
		}

		err := pub(ctx, entcollect.Document{
			ID:        e.ID,
			Kind:      entcollect.KindGroup,
			Action:    action,
			Timestamp: now,
			Fields:    map[string]any{"activedirectory": e, "group.id": e.ID},
		})
		if err != nil {
			return time.Time{}, fmt.Errorf("ad: publish group: %w", err)
		}
		if e.WhenChanged.After(latestWC) {
			latestWC = e.WhenChanged
		}
	}
	return latestWC, nil
}

func (p *Provider) emitDeletions(ctx context.Context, pub entcollect.Publisher, ids *idset.Set, kind entcollect.EntityKind, idField string, now time.Time) error {
	for _, id := range ids.Missing() {
		err := pub(ctx, entcollect.Document{
			ID:        id,
			Kind:      kind,
			Action:    entcollect.ActionDeleted,
			Timestamp: now,
			Fields:    map[string]any{idField: id},
		})
		if err != nil {
			return fmt.Errorf("ad: publish %s deletion: %w", strings.TrimSuffix(idField, ".id"), err)
		}
	}
	return nil
}

func isKeyNotFound(err error) bool {
	return errors.Is(err, entcollect.ErrKeyNotFound)
}

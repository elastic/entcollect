// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package okta_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elastic/entcollect"
	"github.com/elastic/entcollect/provider/okta"
)

func TestFullSync_UsersWithBulkFetchGroups(t *testing.T) {
	now := time.Now()
	fs := &fakeOktaServer{
		users: []okta.User{
			{ID: "u1", Status: "ACTIVE", LastUpdated: now, Profile: map[string]any{"login": "alice@example.com"}},
			{ID: "u2", Status: "ACTIVE", LastUpdated: now, Profile: map[string]any{"login": "bob@example.com"}},
		},
		groups: []okta.Group{
			{ID: "g1", Profile: map[string]any{"name": "Engineering"}},
			{ID: "g2", Profile: map[string]any{"name": "Admin"}},
		},
		members: map[string][]string{
			"g1": {"u1", "u2"},
			"g2": {"u1"},
		},
	}

	p, _ := newTestProvider(t, fs)
	store := newMemStore()

	docs := collectDocs(t.Context(), t, p, store, true)

	userDocs := filterByKind(docs, entcollect.KindUser)
	if len(userDocs) != 2 {
		t.Fatalf("got %d user docs; want 2", len(userDocs))
	}

	for _, doc := range userDocs {
		if doc.Action != entcollect.ActionDiscovered {
			t.Errorf("user %s Action = %v; want ActionDiscovered", doc.ID, doc.Action)
		}
		if doc.Fields["user.id"] != doc.ID {
			t.Errorf("user %s user.id = %v; want %s", doc.ID, doc.Fields["user.id"], doc.ID)
		}
		groups, ok := doc.Fields["groups"].([]okta.Group)
		if !ok {
			t.Fatalf("user %s groups field is %T, want []okta.Group", doc.ID, doc.Fields["groups"])
		}
		switch doc.ID {
		case "u1":
			if len(groups) != 2 {
				t.Errorf("u1 has %d groups; want 2", len(groups))
			}
		case "u2":
			if len(groups) != 1 {
				t.Errorf("u2 has %d groups; want 1", len(groups))
			}
		}
	}

	var cursor time.Time
	if err := store.Get("okta.cursor.user.last_sync", &cursor); err != nil {
		t.Errorf("get cursor: %v", err)
	}
	if cursor.IsZero() {
		t.Error("cursor is zero")
	}
}

func TestFullSync_SubsequentRun(t *testing.T) {
	now := time.Now()
	fs := &fakeOktaServer{
		users: []okta.User{
			{ID: "u1", Status: "ACTIVE", LastUpdated: now},
		},
	}

	p, _ := newTestProvider(t, fs)
	store := newMemStore()

	collectDocs(t.Context(), t, p, store, true)

	docs := collectDocs(t.Context(), t, p, store, true)
	userDocs := filterByKind(docs, entcollect.KindUser)
	if len(userDocs) != 1 {
		t.Fatalf("got %d user docs; want 1", len(userDocs))
	}
	if userDocs[0].Action != entcollect.ActionModified {
		t.Errorf("Action = %v; want ActionModified", userDocs[0].Action)
	}
}

func TestFullSync_Deletion(t *testing.T) {
	now := time.Now()
	fs := &fakeOktaServer{
		users: []okta.User{
			{ID: "u1", Status: "ACTIVE", LastUpdated: now},
			{ID: "u2", Status: "ACTIVE", LastUpdated: now},
		},
	}

	p, _ := newTestProvider(t, fs)
	store := newMemStore()

	collectDocs(t.Context(), t, p, store, true)

	// Remove u2 from the API.
	fs.users = []okta.User{
		{ID: "u1", Status: "ACTIVE", LastUpdated: now},
	}

	docs := collectDocs(t.Context(), t, p, store, true)

	ids := make(map[string]entcollect.Action, len(docs))
	for _, d := range docs {
		ids[d.ID] = d.Action
	}

	if ids["u1"] != entcollect.ActionModified {
		t.Errorf("u1 Action = %v; want ActionModified", ids["u1"])
	}
	if ids["u2"] != entcollect.ActionDeleted {
		t.Errorf("u2 Action = %v; want ActionDeleted", ids["u2"])
	}
}

func TestFullSync_DeprovisionedUser(t *testing.T) {
	now := time.Now()
	fs := &fakeOktaServer{
		users: []okta.User{
			{ID: "u1", Status: "ACTIVE", LastUpdated: now},
			{ID: "u2", Status: "DEPROVISIONED", LastUpdated: now},
		},
	}

	p, _ := newTestProvider(t, fs)
	store := newMemStore()

	docs := collectDocs(t.Context(), t, p, store, true)

	userDocs := filterByKind(docs, entcollect.KindUser)
	if len(userDocs) != 2 {
		t.Fatalf("got %d user docs; want 2 (DEPROVISIONED users are normal entities)", len(userDocs))
	}

	for _, doc := range userDocs {
		if doc.Action != entcollect.ActionDiscovered {
			t.Errorf("user %s Action = %v; want ActionDiscovered (DEPROVISIONED is not a deletion)", doc.ID, doc.Action)
		}
		u, ok := doc.Fields["okta"].(okta.User)
		if !ok {
			continue
		}
		if doc.ID == "u2" && u.Status != "DEPROVISIONED" {
			t.Errorf("u2 status = %q; want DEPROVISIONED", u.Status)
		}
	}
}

func TestFullSync_Supervises(t *testing.T) {
	now := time.Now()
	fs := &fakeOktaServer{
		users: []okta.User{
			{ID: "mgr1", Status: "ACTIVE", LastUpdated: now, Profile: map[string]any{"login": "manager@example.com", "email": "manager@example.com"}},
			{ID: "rep1", Status: "ACTIVE", LastUpdated: now, Profile: map[string]any{"login": "report1@example.com", "email": "report1@example.com", "managerId": "mgr1"}},
			{ID: "rep2", Status: "ACTIVE", LastUpdated: now, Profile: map[string]any{"login": "report2@example.com", "email": "report2@example.com", "managerId": "mgr1"}},
		},
	}

	srv := httptest.NewTLSServer(fs.handler(t))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}

	cfg := okta.DefaultConfig()
	cfg.Domain = u.Host
	cfg.Token = "test-token"
	cfg.LimitFixed = intPtr(1000)
	cfg.EnrichWith = []string{"groups", "supervises"}

	p := okta.NewWithClient(cfg, srv.Client())
	store := newMemStore()

	docs := collectDocs(t.Context(), t, p, store, true)

	for _, doc := range filterByKind(docs, entcollect.KindUser) {
		if doc.ID == "mgr1" {
			subs, ok := doc.Fields["supervises"].([]okta.SupervisedUser)
			if !ok {
				t.Fatalf("mgr1 supervises field is %T; want []okta.SupervisedUser", doc.Fields["supervises"])
			}
			if len(subs) != 2 {
				t.Errorf("mgr1 has %d supervised users; want 2", len(subs))
			}
		}
		if doc.ID == "rep1" || doc.ID == "rep2" {
			if doc.Fields["supervises"] != nil {
				t.Errorf("report %s should not have supervises field", doc.ID)
			}
		}
	}
}

func TestFullSync_DatasetUsers(t *testing.T) {
	now := time.Now()
	fs := &fakeOktaServer{
		users:   []okta.User{{ID: "u1", Status: "ACTIVE", LastUpdated: now}},
		devices: []okta.Device{{ID: "d1", Status: "ACTIVE"}},
	}

	srv := httptest.NewTLSServer(fs.handler(t))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}

	cfg := okta.DefaultConfig()
	cfg.Domain = u.Host
	cfg.Token = "test-token"
	cfg.LimitFixed = intPtr(1000)
	cfg.Dataset = "users"

	p := okta.NewWithClient(cfg, srv.Client())
	store := newMemStore()

	docs := collectDocs(t.Context(), t, p, store, true)

	if devDocs := filterByKind(docs, entcollect.KindDevice); len(devDocs) != 0 {
		t.Errorf("got %d device docs; want 0 (dataset=users should skip devices)", len(devDocs))
	}
	if userDocs := filterByKind(docs, entcollect.KindUser); len(userDocs) != 1 {
		t.Errorf("got %d user docs; want 1", len(userDocs))
	}
}

func TestFullSync_DatasetDevices(t *testing.T) {
	now := time.Now()
	fs := &fakeOktaServer{
		users:    []okta.User{{ID: "u1", Status: "ACTIVE", LastUpdated: now}},
		devices:  []okta.Device{{ID: "d1", Status: "ACTIVE"}},
		devUsers: map[string][]okta.User{"d1": {{ID: "u1"}}},
	}

	srv := httptest.NewTLSServer(fs.handler(t))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}

	cfg := okta.DefaultConfig()
	cfg.Domain = u.Host
	cfg.Token = "test-token"
	cfg.LimitFixed = intPtr(1000)
	cfg.Dataset = "devices"

	p := okta.NewWithClient(cfg, srv.Client())
	store := newMemStore()

	docs := collectDocs(t.Context(), t, p, store, true)

	if userDocs := filterByKind(docs, entcollect.KindUser); len(userDocs) != 0 {
		t.Errorf("got %d user docs; want 0 (dataset=devices should skip users)", len(userDocs))
	}
	devDocs := filterByKind(docs, entcollect.KindDevice)
	if len(devDocs) != 1 {
		t.Fatalf("got %d device docs; want 1", len(devDocs))
	}
	if devDocs[0].Fields["device.id"] != "d1" {
		t.Errorf("device.id = %v; want d1", devDocs[0].Fields["device.id"])
	}
}

func TestFullSync_DeviceDeletion(t *testing.T) {
	fs := &fakeOktaServer{
		devices: []okta.Device{
			{ID: "d1", Status: "ACTIVE"},
			{ID: "d2", Status: "ACTIVE"},
		},
		devUsers: map[string][]okta.User{},
	}

	srv := httptest.NewTLSServer(fs.handler(t))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}

	cfg := okta.DefaultConfig()
	cfg.Domain = u.Host
	cfg.Token = "test-token"
	cfg.LimitFixed = intPtr(1000)
	cfg.Dataset = "devices"

	p := okta.NewWithClient(cfg, srv.Client())
	store := newMemStore()

	collectDocs(t.Context(), t, p, store, true)

	// Remove d2
	fs.devices = []okta.Device{{ID: "d1", Status: "ACTIVE"}}

	docs := collectDocs(t.Context(), t, p, store, true)
	ids := make(map[string]entcollect.Action, len(docs))
	for _, d := range docs {
		ids[d.ID] = d.Action
	}
	if ids["d1"] != entcollect.ActionModified {
		t.Errorf("d1 Action = %v; want ActionModified", ids["d1"])
	}
	if ids["d2"] != entcollect.ActionDeleted {
		t.Errorf("d2 Action = %v; want ActionDeleted", ids["d2"])
	}
}

func TestIncrementalSync_PerUserGroups(t *testing.T) {
	now := time.Now()
	fs := &fakeOktaServer{
		users: []okta.User{
			{ID: "u1", Status: "ACTIVE", LastUpdated: now, Profile: map[string]any{"login": "alice@example.com"}},
		},
		groups: []okta.Group{
			{ID: "g1", Profile: map[string]any{"name": "Engineering"}},
		},
		members: map[string][]string{"g1": {"u1"}},
	}

	p, _ := newTestProvider(t, fs)
	store := newMemStore()

	// Run full sync first to establish cursor.
	collectDocs(t.Context(), t, p, store, true)

	// Add a new user that will appear in incremental.
	fs.users = append(fs.users, okta.User{
		ID: "u3", Status: "ACTIVE", LastUpdated: now.Add(time.Hour),
		Profile: map[string]any{"login": "charlie@example.com"},
	})
	fs.members["g1"] = append(fs.members["g1"], "u3")

	docs := collectDocs(t.Context(), t, p, store, false)

	userDocs := filterByKind(docs, entcollect.KindUser)
	// Incremental returns all users matching the search filter.
	// The exact count depends on the mock's filtering, but all
	// should have Action=ActionModified (incremental always uses Modified).
	for _, doc := range userDocs {
		if doc.Action != entcollect.ActionModified {
			t.Errorf("user %s Action = %v; want ActionModified (incremental)", doc.ID, doc.Action)
		}
		if _, ok := doc.Fields["groups"]; !ok {
			t.Errorf("user %s missing groups field (per-user group resolution)", doc.ID)
		}
	}

	var cursor time.Time
	if err := store.Get("okta.cursor.user.last_update", &cursor); err != nil {
		t.Errorf("get last_update cursor: %v", err)
	}
	if cursor.IsZero() {
		t.Errorf("last_update cursor is zero")
	}
}

func TestFullSync_EnrichmentSkipsDeletedEntities(t *testing.T) {
	now := time.Now()
	fs := &fakeOktaServer{
		users: []okta.User{
			{ID: "u1", Status: "ACTIVE", LastUpdated: now},
			{ID: "u2", Status: "ACTIVE", LastUpdated: now},
		},
		roles: map[string][]okta.Role{
			"u1": {{ID: "ra1", RoleID: "cr-deleted", Type: "CUSTOM", Label: "Deleted role"}},
			"u2": {{ID: "ra2", RoleID: "cr-live", Type: "CUSTOM", Label: "Live role"}},
		},
		perms: map[string][]okta.Permission{
			"cr-live": {{Label: "okta.users.read"}},
		},
		// u1 was deleted between the bulk user fetch and its factors
		// enrichment call, and u1's custom role definition was deleted:
		// both enrichment calls return 404.
		fail: map[string]int{
			"/api/v1/users/u1/factors":                 http.StatusNotFound,
			"/api/v1/iam/roles/cr-deleted/permissions": http.StatusNotFound,
		},
	}

	srv := httptest.NewTLSServer(fs.handler(t))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}

	cfg := okta.DefaultConfig()
	cfg.Domain = u.Host
	cfg.Token = "test-token"
	cfg.LimitFixed = intPtr(1000)
	cfg.Dataset = "users"
	cfg.EnrichWith = []string{"factors", "roles", "permissions"}

	p := okta.NewWithClient(cfg, srv.Client())
	store := newMemStore()

	docs := collectDocs(t.Context(), t, p, store, true)

	userDocs := filterByKind(docs, entcollect.KindUser)
	if len(userDocs) != 2 {
		t.Fatalf("got %d user docs; want 2 (enrichment failures must not abort the sync)", len(userDocs))
	}
	for _, doc := range userDocs {
		roles, ok := doc.Fields["roles"].([]okta.Role)
		if !ok || len(roles) != 1 {
			t.Errorf("user %s roles = %v; want 1 role", doc.ID, doc.Fields["roles"])
			continue
		}
		switch doc.ID {
		case "u1":
			if _, ok := doc.Fields["factors"]; ok {
				t.Errorf("user u1 has factors field; want enrichment skipped")
			}
			if len(roles[0].Permissions) != 0 {
				t.Errorf("user u1 role permissions = %v; want none (enrichment skipped)", roles[0].Permissions)
			}
		case "u2":
			if _, ok := doc.Fields["factors"]; !ok {
				t.Errorf("user u2 missing factors field")
			}
			if len(roles[0].Permissions) != 1 {
				t.Errorf("user u2 role permissions = %v; want 1", roles[0].Permissions)
			}
		}
	}
}

func TestIncrementalSync_GroupsEnrichmentSkipsDeletedUser(t *testing.T) {
	now := time.Now()
	fs := &fakeOktaServer{
		users: []okta.User{
			{ID: "u1", Status: "ACTIVE", LastUpdated: now},
			{ID: "u2", Status: "ACTIVE", LastUpdated: now},
		},
		groups:  []okta.Group{{ID: "g1", Profile: map[string]any{"name": "Engineering"}}},
		members: map[string][]string{"g1": {"u1", "u2"}},
		// u1 was deleted between the bulk user fetch and its per-user
		// groups enrichment call.
		fail: map[string]int{"/api/v1/users/u1/groups": http.StatusNotFound},
	}

	p, _ := newTestProvider(t, fs)
	store := newMemStore()

	docs := collectDocs(t.Context(), t, p, store, false)

	userDocs := filterByKind(docs, entcollect.KindUser)
	if len(userDocs) != 2 {
		t.Fatalf("got %d user docs; want 2 (groups enrichment failure must not abort the sync)", len(userDocs))
	}
	for _, doc := range userDocs {
		_, hasGroups := doc.Fields["groups"]
		switch doc.ID {
		case "u1":
			if hasGroups {
				t.Errorf("user u1 has groups field; want enrichment skipped")
			}
		case "u2":
			if !hasGroups {
				t.Errorf("user u2 missing groups field")
			}
		}
	}
}

func TestFullSync_EnrichmentContextCanceledAborts(t *testing.T) {
	now := time.Now()
	fs := &fakeOktaServer{
		users: []okta.User{
			{ID: "u1", Status: "ACTIVE", LastUpdated: now},
			{ID: "u2", Status: "ACTIVE", LastUpdated: now},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Cancel the sync context during u1's factors enrichment call. The
	// sync must abort promptly rather than warn-and-continue through
	// the remaining users.
	fs.onRequest = func(r *http.Request) {
		if r.URL.Path == "/api/v1/users/u1/factors" {
			cancel()
		}
	}

	srv := httptest.NewTLSServer(fs.handler(t))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}

	cfg := okta.DefaultConfig()
	cfg.Domain = u.Host
	cfg.Token = "test-token"
	cfg.LimitFixed = intPtr(1000)
	cfg.Dataset = "users"
	cfg.EnrichWith = []string{"factors"}

	p := okta.NewWithClient(cfg, srv.Client())
	store := newMemStore()

	log := slog.New(slog.NewTextHandler(newTestLogWriter(t), nil))
	pub := func(context.Context, entcollect.Document) error { return nil }
	err = p.FullSync(ctx, store, pub, log)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("FullSync error = %v; want context.Canceled", err)
	}
}

func TestIncrementalSync_NoIdsetOperations(t *testing.T) {
	now := time.Now()
	fs := &fakeOktaServer{
		users: []okta.User{
			{ID: "u1", Status: "ACTIVE", LastUpdated: now},
			{ID: "u2", Status: "ACTIVE", LastUpdated: now},
		},
	}

	p, _ := newTestProvider(t, fs)
	store := newMemStore()

	// Full sync establishes idset with u1 and u2.
	collectDocs(t.Context(), t, p, store, true)

	// Incremental only sees u1 (u2 unchanged).
	fs.users = []okta.User{
		{ID: "u1", Status: "ACTIVE", LastUpdated: now.Add(time.Hour)},
	}

	docs := collectDocs(t.Context(), t, p, store, false)

	// No deletions should appear — incremental doesn't touch idsets.
	deleted := filterByAction(docs, entcollect.ActionDeleted)
	if len(deleted) != 0 {
		t.Errorf("got %d deleted docs; want 0 (incremental must not emit deletions)", len(deleted))
	}

	// Full sync again — u2 should now be deleted since it's gone from the API.
	docs = collectDocs(t.Context(), t, p, store, true)
	deleted = filterByAction(docs, entcollect.ActionDeleted)
	if len(deleted) != 1 {
		t.Fatalf("got %d deleted docs; want 1", len(deleted))
	}
	if deleted[0].ID != "u2" {
		t.Errorf("deleted ID = %q; want u2", deleted[0].ID)
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*okta.Config)
		wantErr bool
	}{
		{
			name:   "valid with token",
			modify: func(c *okta.Config) {},
		},
		{
			name:    "missing domain",
			modify:  func(c *okta.Config) { c.Domain = "" },
			wantErr: true,
		},
		{
			name:    "no auth",
			modify:  func(c *okta.Config) { c.Token = "" },
			wantErr: true,
		},
		{
			name:    "both auth",
			modify:  func(c *okta.Config) { c.OAuth2 = &okta.OAuth2Config{} },
			wantErr: true,
		},
		{
			name:    "invalid dataset",
			modify:  func(c *okta.Config) { c.Dataset = "invalid" },
			wantErr: true,
		},
		{
			name:    "invalid enrichment",
			modify:  func(c *okta.Config) { c.EnrichWith = []string{"bogus"} },
			wantErr: true,
		},
		{
			name:    "sync <= update",
			modify:  func(c *okta.Config) { c.SyncInterval = c.UpdateInterval },
			wantErr: true,
		},
		{
			name: "valid oauth2 with secret",
			modify: func(c *okta.Config) {
				c.Token = ""
				c.OAuth2 = &okta.OAuth2Config{
					ClientID:     "client-id",
					ClientSecret: "client-secret",
					TokenURL:     "https://example.okta.com/oauth2/v1/token",
					Scopes:       []string{"okta.users.read"},
				}
			},
		},
		{
			name: "valid oauth2 with jwk",
			modify: func(c *okta.Config) {
				c.Token = ""
				c.OAuth2 = &okta.OAuth2Config{
					ClientID: "client-id",
					TokenURL: "https://example.okta.com/oauth2/v1/token",
					Scopes:   []string{"okta.users.read"},
					JWK:      []byte(`{"kty":"RSA"}`),
				}
			},
		},
		{
			name: "oauth2 missing client_id",
			modify: func(c *okta.Config) {
				c.Token = ""
				c.OAuth2 = &okta.OAuth2Config{
					ClientSecret: "secret",
					TokenURL:     "https://example.okta.com/oauth2/v1/token",
					Scopes:       []string{"okta.users.read"},
				}
			},
			wantErr: true,
		},
		{
			name: "oauth2 missing token_url",
			modify: func(c *okta.Config) {
				c.Token = ""
				c.OAuth2 = &okta.OAuth2Config{
					ClientID:     "client-id",
					ClientSecret: "secret",
					Scopes:       []string{"okta.users.read"},
				}
			},
			wantErr: true,
		},
		{
			name: "oauth2 missing scopes",
			modify: func(c *okta.Config) {
				c.Token = ""
				c.OAuth2 = &okta.OAuth2Config{
					ClientID:     "client-id",
					ClientSecret: "secret",
					TokenURL:     "https://example.okta.com/oauth2/v1/token",
				}
			},
			wantErr: true,
		},
		{
			name: "oauth2 no credentials",
			modify: func(c *okta.Config) {
				c.Token = ""
				c.OAuth2 = &okta.OAuth2Config{
					ClientID: "client-id",
					TokenURL: "https://example.okta.com/oauth2/v1/token",
					Scopes:   []string{"okta.users.read"},
				}
			},
			wantErr: true,
		},
		{
			name: "oauth2 both credentials",
			modify: func(c *okta.Config) {
				c.Token = ""
				c.OAuth2 = &okta.OAuth2Config{
					ClientID:     "client-id",
					ClientSecret: "secret",
					TokenURL:     "https://example.okta.com/oauth2/v1/token",
					Scopes:       []string{"okta.users.read"},
					JWK:          []byte(`{"kty":"RSA"}`),
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := okta.DefaultConfig()
			cfg.Domain = "example.okta.com"
			cfg.Token = "test-token"
			tt.modify(&cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v; wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

// Test helpers below.

type memStore struct {
	data map[string]json.RawMessage
}

func newMemStore() *memStore {
	return &memStore{data: make(map[string]json.RawMessage)}
}

func (m *memStore) Get(key string, dst any) error {
	raw, ok := m.data[key]
	if !ok {
		return fmt.Errorf("memstore get %q: %w", key, entcollect.ErrKeyNotFound)
	}
	return json.Unmarshal(raw, dst)
}

func (m *memStore) Set(key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	m.data[key] = raw
	return nil
}

func (m *memStore) Delete(key string) error {
	delete(m.data, key)
	return nil
}

func (m *memStore) Each(fn func(string, func(any) error) (bool, error)) error {
	for k, v := range m.data {
		v := v
		cont, err := fn(k, func(dst any) error { return json.Unmarshal(v, dst) })
		if err != nil {
			return err
		}
		if !cont {
			return nil
		}
	}
	return nil
}

// fakeOktaServer provides configurable mock Okta API responses.
type fakeOktaServer struct {
	users     []okta.User
	groups    []okta.Group
	members   map[string][]string // group ID → user IDs
	devices   []okta.Device
	devUsers  map[string][]okta.User       // device ID → users
	roles     map[string][]okta.Role       // user ID → role assignments
	perms     map[string][]okta.Permission // role ID → permissions
	fail      map[string]int               // URL path → HTTP status to return
	onRequest func(r *http.Request)        // optional hook, called before dispatch
	requests  atomic.Int64
}

func (fs *fakeOktaServer) resetRequests()      { fs.requests.Store(0) }
func (fs *fakeOktaServer) requestCount() int64 { return fs.requests.Load() }

func (fs *fakeOktaServer) handler(tb testing.TB) http.Handler {
	tb.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(fs.users)
		if err != nil {
			tb.Errorf("encode users: %v", err)
		}
	})

	mux.HandleFunc("GET /api/v1/groups", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(fs.groups)
		if err != nil {
			tb.Errorf("encode groups: %v", err)
		}
	})

	mux.HandleFunc("GET /api/v1/groups/{groupId}/users", func(w http.ResponseWriter, r *http.Request) {
		gid := r.PathValue("groupId")
		memberIDs := fs.members[gid]
		var result []okta.User
		for _, uid := range memberIDs {
			for _, u := range fs.users {
				if u.ID == uid {
					result = append(result, u)
					break
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(result)
		if err != nil {
			tb.Errorf("encode group members: %v", err)
		}
	})

	mux.HandleFunc("GET /api/v1/users/{userId}/groups", func(w http.ResponseWriter, r *http.Request) {
		uid := r.PathValue("userId")
		var result []okta.Group
		for _, g := range fs.groups {
			for _, mid := range fs.members[g.ID] {
				if mid == uid {
					result = append(result, g)
					break
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(result)
		if err != nil {
			tb.Errorf("encode user groups: %v", err)
		}
	})

	mux.HandleFunc("GET /api/v1/devices", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(fs.devices)
		if err != nil {
			tb.Errorf("encode devices: %v", err)
		}
	})

	mux.HandleFunc("GET /api/v1/devices/{deviceId}/users", func(w http.ResponseWriter, r *http.Request) {
		did := r.PathValue("deviceId")
		users := fs.devUsers[did]
		type wrapped struct {
			User okta.User `json:"user"`
		}
		var result []wrapped
		for _, u := range users {
			result = append(result, wrapped{User: u})
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(result)
		if err != nil {
			tb.Errorf("encode device users: %v", err)
		}
	})

	mux.HandleFunc("GET /api/v1/users/{userId}/factors", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode([]okta.Factor{})
		if err != nil {
			tb.Errorf("encode factors: %v", err)
		}
	})

	mux.HandleFunc("GET /api/v1/users/{userId}/roles", func(w http.ResponseWriter, r *http.Request) {
		roles := fs.roles[r.PathValue("userId")]
		if roles == nil {
			roles = []okta.Role{}
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(roles)
		if err != nil {
			tb.Errorf("encode roles: %v", err)
		}
	})

	mux.HandleFunc("GET /api/v1/iam/roles/{roleId}/permissions", func(w http.ResponseWriter, r *http.Request) {
		perms := fs.perms[r.PathValue("roleId")]
		if perms == nil {
			perms = []okta.Permission{}
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(map[string][]okta.Permission{"permissions": perms})
		if err != nil {
			tb.Errorf("encode permissions: %v", err)
		}
	})

	mux.HandleFunc("GET /api/v1/users/{userId}/devices", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode([]okta.Device{})
		if err != nil {
			tb.Errorf("encode user devices: %v", err)
		}
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.requests.Add(1)
		if fs.onRequest != nil {
			fs.onRequest(r)
		}
		if status, ok := fs.fail[r.URL.Path]; ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			fmt.Fprintf(w, `{"errorCode":"E0000007","errorSummary":"Not found: %s"}`, r.URL.Path)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func newTestProvider(t *testing.T, fs *fakeOktaServer) (*okta.Provider, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(fs.handler(t))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}

	cfg := okta.DefaultConfig()
	cfg.Domain = u.Host
	cfg.Token = "test-token"
	cfg.LimitFixed = intPtr(1000)

	return okta.NewWithClient(cfg, srv.Client()), srv
}

func collectDocs(ctx context.Context, t *testing.T, p *okta.Provider, store entcollect.Store, full bool) []entcollect.Document {
	t.Helper()
	var docs []entcollect.Document
	pub := func(_ context.Context, doc entcollect.Document) error {
		docs = append(docs, doc)
		return nil
	}
	log := slog.New(slog.NewTextHandler(newTestLogWriter(t), nil))

	var err error
	if full {
		err = p.FullSync(ctx, store, pub, log)
	} else {
		err = p.IncrementalSync(ctx, store, pub, log)
	}
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	return docs
}

type testLogWriter struct{ t *testing.T }

func newTestLogWriter(t *testing.T) *testLogWriter { return &testLogWriter{t: t} }

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

func intPtr(i int) *int { return &i }

func filterByKind(docs []entcollect.Document, kind entcollect.EntityKind) []entcollect.Document {
	var result []entcollect.Document
	for _, d := range docs {
		if d.Kind == kind {
			result = append(result, d)
		}
	}
	return result
}

func filterByAction(docs []entcollect.Document, action entcollect.Action) []entcollect.Document {
	var result []entcollect.Document
	for _, d := range docs {
		if d.Action == action {
			result = append(result, d)
		}
	}
	return result
}

func BenchmarkOktaFullSync(b *testing.B) {
	for _, tc := range []struct {
		users  int
		groups int
	}{
		{10, 1},
		{100, 10},
		{1000, 10},
		{1000, 50},
	} {
		name := fmt.Sprintf("users=%d/groups=%d", tc.users, tc.groups)
		b.Run(name, func(b *testing.B) {
			groups, members := generateOktaGroups(tc.groups, tc.users)
			fs := &fakeOktaServer{
				users:   generateOktaUsers(tc.users),
				groups:  groups,
				members: members,
			}
			p := newBenchOktaProvider(b, fs)

			log := slog.New(slog.NewTextHandler(&noopWriter{}, nil))
			ctx := context.Background()

			b.ReportAllocs()
			fs.resetRequests()
			b.ResetTimer()
			var lastDocs []entcollect.Document
			for range b.N {
				store := newMemStore()
				lastDocs = lastDocs[:0]
				pub := func(_ context.Context, doc entcollect.Document) error {
					lastDocs = append(lastDocs, doc)
					return nil
				}
				err := p.FullSync(ctx, store, pub, log)
				if err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(fs.requestCount())/float64(b.N), "api-calls/op")
			if len(lastDocs) > 0 {
				total := docFieldsBytes(lastDocs)
				b.ReportMetric(float64(total)/float64(len(lastDocs)), "bytes/doc")
			}
		})
	}
}

func BenchmarkOktaIncrementalSync(b *testing.B) {
	for _, tc := range []struct {
		users  int
		groups int
	}{
		{10, 1},
		{100, 10},
		{1000, 10},
		{1000, 50},
	} {
		name := fmt.Sprintf("users=%d/groups=%d", tc.users, tc.groups)
		b.Run(name, func(b *testing.B) {
			groups, members := generateOktaGroups(tc.groups, tc.users)
			fs := &fakeOktaServer{
				users:   generateOktaUsers(tc.users),
				groups:  groups,
				members: members,
			}
			p := newBenchOktaProvider(b, fs)

			log := slog.New(slog.NewTextHandler(&noopWriter{}, nil))
			ctx := context.Background()

			// Establish initial state.
			store := newMemStore()
			var docs []entcollect.Document
			pub := func(_ context.Context, doc entcollect.Document) error {
				docs = append(docs, doc)
				return nil
			}
			err := p.FullSync(ctx, store, pub, log)
			if err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			fs.resetRequests()
			b.ResetTimer()
			for range b.N {
				docs = docs[:0]
				err = p.IncrementalSync(ctx, store, pub, log)
				if err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(fs.requestCount())/float64(b.N), "api-calls/op")
		})
	}
}

func generateOktaUsers(n int) []okta.User {
	now := time.Now()
	users := make([]okta.User, n)
	for i := range n {
		users[i] = okta.User{
			ID:          fmt.Sprintf("u%d", i),
			Status:      "ACTIVE",
			LastUpdated: now,
			Profile:     map[string]any{"login": fmt.Sprintf("user%d@example.com", i)},
		}
	}
	return users
}

// generateOktaGroups creates nGroups groups and distributes nUsers user IDs
// across them round-robin so each group gets roughly nUsers/nGroups members.
func generateOktaGroups(nGroups, nUsers int) ([]okta.Group, map[string][]string) {
	groups := make([]okta.Group, nGroups)
	members := make(map[string][]string, nGroups)
	for i := range nGroups {
		gid := fmt.Sprintf("g%d", i)
		groups[i] = okta.Group{ID: gid, Profile: map[string]any{"name": fmt.Sprintf("Group %d", i)}}
		ms := make([]string, 0, nUsers/nGroups+1)
		for j := range nUsers {
			if j%nGroups == i {
				ms = append(ms, fmt.Sprintf("u%d", j))
			}
		}
		members[gid] = ms
	}
	return groups, members
}

func newBenchOktaProvider(b *testing.B, fs *fakeOktaServer) *okta.Provider {
	b.Helper()
	srv := httptest.NewTLSServer(fs.handler(b))
	b.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		b.Fatalf("parse server URL: %v", err)
	}

	cfg := okta.DefaultConfig()
	cfg.Domain = u.Host
	cfg.Token = "test-token"
	cfg.LimitFixed = intPtr(100000)
	return okta.NewWithClient(cfg, srv.Client())
}

type noopWriter struct{}

func (noopWriter) Write(p []byte) (int, error) { return len(p), nil }

func docFieldsBytes(docs []entcollect.Document) int {
	total := 0
	for _, d := range docs {
		b, _ := json.Marshal(d.Fields)
		total += len(b)
	}
	return total
}

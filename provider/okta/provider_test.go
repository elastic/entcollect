// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package okta_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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

	srv := httptest.NewTLSServer(fs.handler())
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

	srv := httptest.NewTLSServer(fs.handler())
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

	srv := httptest.NewTLSServer(fs.handler())
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

	srv := httptest.NewTLSServer(fs.handler())
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
	users    []okta.User
	groups   []okta.Group
	members  map[string][]string // group ID → user IDs
	devices  []okta.Device
	devUsers map[string][]okta.User // device ID → users
}

func (fs *fakeOktaServer) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(fs.users) //nolint:errcheck
	})

	mux.HandleFunc("GET /api/v1/groups", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(fs.groups) //nolint:errcheck
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
		json.NewEncoder(w).Encode(result) //nolint:errcheck
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
		json.NewEncoder(w).Encode(result) //nolint:errcheck
	})

	mux.HandleFunc("GET /api/v1/devices", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(fs.devices) //nolint:errcheck
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
		json.NewEncoder(w).Encode(result) //nolint:errcheck
	})

	mux.HandleFunc("GET /api/v1/users/{userId}/factors", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]okta.Factor{}) //nolint:errcheck
	})

	mux.HandleFunc("GET /api/v1/users/{userId}/roles", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]okta.Role{}) //nolint:errcheck
	})

	mux.HandleFunc("GET /api/v1/users/{userId}/devices", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]okta.Device{}) //nolint:errcheck
	})

	return mux
}

func newTestProvider(t *testing.T, fs *fakeOktaServer) (*okta.Provider, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(fs.handler())
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

func (w *testLogWriter) Write(p []byte) (int, error) {
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

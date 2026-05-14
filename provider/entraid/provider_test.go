// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package entraid

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/elastic/entcollect"
)

func TestFullSync_InitialFetch(t *testing.T) {
	srv, cfg := startTestGraph(t, testGraphOpts{
		fullUsers: []json.RawMessage{
			rawUser("u1", map[string]any{"displayName": "Alice"}),
			rawUser("u2", map[string]any{"displayName": "Bob"}),
		},
		fullDevices: []json.RawMessage{
			rawDevice("d1", map[string]any{"displayName": "Laptop"}),
		},
		groups: []Group{
			{ID: "g1", DisplayName: "Engineering"},
		},
		groupMembers: map[string][]Member{
			"g1": {
				{ID: "u1", Type: odataTypeUser},
				{ID: "d1", Type: odataTypeDevice},
			},
		},
		deviceOwners: map[string][]map[string]any{
			"d1": {{"id": "u1", "displayName": "Alice"}},
		},
		deviceUsers: map[string][]map[string]any{},
	})
	defer srv.Close()

	p := NewWithClient(cfg, srv.Client())
	store := newTestStore()
	docs := collectDocs(context.Background(), t, p, store, true)

	if len(docs) != 3 {
		t.Fatalf("got %d docs; want 3 (2 users + 1 device)", len(docs))
	}

	sort.Slice(docs, func(i, j int) bool { return docs[i].ID < docs[j].ID })

	// d1
	if docs[0].ID != "d1" || docs[0].Kind != entcollect.KindDevice {
		t.Errorf("docs[0] = %s/%v; want d1/device", docs[0].ID, docs[0].Kind)
	}
	if docs[0].Action != entcollect.ActionDiscovered {
		t.Errorf("d1 action = %v; want discovered", docs[0].Action)
	}
	dg, ok := docs[0].Fields["device.group"].([]GroupECS)
	if !ok || len(dg) != 1 || dg[0].ID != "g1" {
		t.Errorf("d1 device.group = %v; want [{g1 Engineering}]", docs[0].Fields["device.group"])
	}
	if docs[0].Fields["device.registered_owners"] == nil {
		t.Error("d1 should have registered_owners")
	}

	// u1
	if docs[1].ID != "u1" || docs[1].Action != entcollect.ActionDiscovered {
		t.Errorf("docs[1] = %s/%v; want u1/discovered", docs[1].ID, docs[1].Action)
	}
	ug, ok := docs[1].Fields["user.group"].([]GroupECS)
	if !ok || len(ug) != 1 || ug[0].ID != "g1" {
		t.Errorf("u1 user.group = %v; want [{g1 Engineering}]", docs[1].Fields["user.group"])
	}

	// u2
	if docs[2].ID != "u2" || docs[2].Action != entcollect.ActionDiscovered {
		t.Errorf("docs[2] = %s/%v; want u2/discovered", docs[2].ID, docs[2].Action)
	}
	if docs[2].Fields["user.group"] != nil {
		t.Errorf("u2 should have no group membership, got %v", docs[2].Fields["user.group"])
	}

	// Delta link stored.
	var dl string
	if err := store.Get(keyCursorUsersDelta, &dl); err != nil {
		t.Errorf("load user delta link: %v", err)
	}
	if dl == "" {
		t.Error("user delta link should be stored")
	}
}

func TestIncrementalSync_WithChanges(t *testing.T) {
	srv, cfg := startTestGraph(t, testGraphOpts{
		fullUsers: []json.RawMessage{
			rawUser("u1", map[string]any{"displayName": "Alice"}),
			rawUser("u2", map[string]any{"displayName": "Bob"}),
		},
		deltaUsers: []json.RawMessage{
			rawUser("u1", map[string]any{"displayName": "Alice Updated"}),
			rawRemovedUser("u2"),
		},
		fullDevices: []json.RawMessage{},
		groups: []Group{
			{ID: "g1", DisplayName: "Engineering"},
		},
		groupMembers: map[string][]Member{
			"g1": {{ID: "u1", Type: odataTypeUser}},
		},
		deviceOwners: map[string][]map[string]any{},
		deviceUsers:  map[string][]map[string]any{},
	})
	defer srv.Close()

	p := NewWithClient(cfg, srv.Client())
	store := newTestStore()

	// Full sync first to populate delta links.
	_ = collectDocs(context.Background(), t, p, store, true)

	// Incremental — should get delta results.
	docs := collectDocs(context.Background(), t, p, store, false)

	sort.Slice(docs, func(i, j int) bool { return docs[i].ID < docs[j].ID })
	if len(docs) != 2 {
		t.Fatalf("got %d docs; want 2 changed users", len(docs))
	}

	if docs[0].ID != "u1" || docs[0].Action != entcollect.ActionModified {
		t.Errorf("docs[0] = %s/%v; want u1/modified", docs[0].ID, docs[0].Action)
	}
	if docs[1].ID != "u2" || docs[1].Action != entcollect.ActionDeleted {
		t.Errorf("docs[1] = %s/%v; want u2/deleted", docs[1].ID, docs[1].Action)
	}
}

func TestIncrementalSync_NoChanges(t *testing.T) {
	srv, cfg := startTestGraph(t, testGraphOpts{
		fullUsers:    []json.RawMessage{rawUser("u1", nil)},
		deltaUsers:   []json.RawMessage{},
		fullDevices:  []json.RawMessage{},
		deltaDevices: []json.RawMessage{},
		groups:       []Group{{ID: "g1", DisplayName: "G1"}},
		groupMembers: map[string][]Member{
			"g1": {{ID: "u1", Type: odataTypeUser}},
		},
		deviceOwners: map[string][]map[string]any{},
		deviceUsers:  map[string][]map[string]any{},
	})
	defer srv.Close()

	p := NewWithClient(cfg, srv.Client())
	store := newTestStore()

	_ = collectDocs(context.Background(), t, p, store, true)
	docs := collectDocs(context.Background(), t, p, store, false)

	if len(docs) != 0 {
		t.Errorf("got %d docs; want 0 (no changes)", len(docs))
	}
}

func TestFullSync_TransitiveGroupMembership(t *testing.T) {
	srv, cfg := startTestGraph(t, testGraphOpts{
		fullUsers:   []json.RawMessage{rawUser("u1", nil)},
		fullDevices: []json.RawMessage{},
		groups: []Group{
			{ID: "a", DisplayName: "A"},
			{ID: "b", DisplayName: "B"},
			{ID: "c", DisplayName: "C"},
		},
		groupMembers: map[string][]Member{
			"a": {{ID: "u1", Type: odataTypeUser}},
			"b": {{ID: "a", Type: odataTypeGroup}},
			"c": {{ID: "b", Type: odataTypeGroup}},
		},
		deviceOwners: map[string][]map[string]any{},
		deviceUsers:  map[string][]map[string]any{},
	})
	defer srv.Close()

	p := NewWithClient(cfg, srv.Client())
	store := newTestStore()
	docs := collectDocs(context.Background(), t, p, store, true)

	if len(docs) != 1 {
		t.Fatalf("got %d docs; want 1", len(docs))
	}

	gs, ok := docs[0].Fields["user.group"].([]GroupECS)
	if !ok {
		t.Fatalf("user.group is %T; want []GroupECS", docs[0].Fields["user.group"])
	}
	sortGroups(gs)
	ids := groupIDs(gs)
	want := []string{"a", "b", "c"}
	if len(ids) != 3 {
		t.Fatalf("transitive groups = %v; want %v", ids, want)
	}
	for i := range ids {
		if ids[i] != want[i] {
			t.Errorf("groups[%d] = %s; want %s", i, ids[i], want[i])
		}
	}
}

func TestIncrementalSync_ExpiredDeltaLink(t *testing.T) {
	var userCalls atomic.Int32
	var srvURL string

	mux := http.NewServeMux()
	mux.HandleFunc("POST /tenant-1/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(authTokenResponse{
			AccessToken: "test-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	})
	mux.HandleFunc("GET /v1.0/users/delta", func(w http.ResponseWriter, r *http.Request) {
		n := userCalls.Add(1)
		switch n {
		case 1:
			// Full sync: return users with delta link.
			json.NewEncoder(w).Encode(deltaResponse[json.RawMessage]{
				Value:     []json.RawMessage{rawUser("u1", nil)},
				DeltaLink: srvURL + "/v1.0/users/delta?$deltatoken=will-expire",
			})
		case 2:
			// Incremental with "expired" delta link: return 410.
			w.WriteHeader(http.StatusGone)
		case 3:
			// Retry without delta link: return new data.
			json.NewEncoder(w).Encode(deltaResponse[json.RawMessage]{
				Value:     []json.RawMessage{rawUser("u1", nil)},
				DeltaLink: srvURL + "/v1.0/users/delta?$deltatoken=fresh",
			})
		}
	})
	mux.HandleFunc("GET /v1.0/devices/delta", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(deltaResponse[json.RawMessage]{
			DeltaLink: srvURL + "/v1.0/devices/delta?$deltatoken=latest",
		})
	})
	mux.HandleFunc("GET /v1.0/groups", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(deltaResponse[Group]{})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()
	srvURL = srv.URL

	cfg := DefaultConfig()
	cfg.TenantID = "tenant-1"
	cfg.ClientID = "client-1"
	cfg.ClientSecret = "secret-1"
	cfg.LoginEndpoint = srv.URL
	cfg.APIEndpoint = srv.URL + "/v1.0"

	p := NewWithClient(cfg, srv.Client())
	store := newTestStore()

	_ = collectDocs(context.Background(), t, p, store, true)
	docs := collectDocs(context.Background(), t, p, store, false)

	if len(docs) != 1 {
		t.Fatalf("got %d docs; want 1 (recovered from expired delta link)", len(docs))
	}
}

func TestFullSync_DatasetUsers(t *testing.T) {
	srv, cfg := startTestGraph(t, testGraphOpts{
		fullUsers:    []json.RawMessage{rawUser("u1", nil)},
		fullDevices:  []json.RawMessage{rawDevice("d1", nil)},
		groups:       []Group{},
		groupMembers: map[string][]Member{},
		deviceOwners: map[string][]map[string]any{},
		deviceUsers:  map[string][]map[string]any{},
	})
	defer srv.Close()

	cfg.Dataset = "users"
	p := NewWithClient(cfg, srv.Client())
	store := newTestStore()
	docs := collectDocs(context.Background(), t, p, store, true)

	for _, doc := range docs {
		if doc.Kind != entcollect.KindUser {
			t.Errorf("dataset=users emitted %v; want only users", doc.Kind)
		}
	}
}

func TestFullSync_DatasetDevices(t *testing.T) {
	srv, cfg := startTestGraph(t, testGraphOpts{
		fullUsers:    []json.RawMessage{rawUser("u1", nil)},
		fullDevices:  []json.RawMessage{rawDevice("d1", nil)},
		groups:       []Group{},
		groupMembers: map[string][]Member{},
		deviceOwners: map[string][]map[string]any{},
		deviceUsers:  map[string][]map[string]any{},
	})
	defer srv.Close()

	cfg.Dataset = "devices"
	p := NewWithClient(cfg, srv.Client())
	store := newTestStore()
	docs := collectDocs(context.Background(), t, p, store, true)

	for _, doc := range docs {
		if doc.Kind != entcollect.KindDevice {
			t.Errorf("dataset=devices emitted %v; want only devices", doc.Kind)
		}
	}
}

func TestFullSync_MFAEnrichment(t *testing.T) {
	type mfaEntry struct {
		ID string `json:"id"`
		MFADetails
	}
	srv, cfg := startTestGraph(t, testGraphOpts{
		fullUsers: []json.RawMessage{
			rawUser("u1", map[string]any{"displayName": "Alice"}),
			rawUser("u2", map[string]any{"displayName": "Bob"}),
		},
		fullDevices:  []json.RawMessage{},
		groups:       []Group{},
		groupMembers: map[string][]Member{},
		deviceOwners: map[string][]map[string]any{},
		deviceUsers:  map[string][]map[string]any{},
		mfaResponse: deltaResponse[mfaEntry]{
			Value: []mfaEntry{
				{
					ID: "u1",
					MFADetails: MFADetails{
						IsMFACapable:    true,
						IsMFARegistered: true,
					},
				},
			},
		},
	})
	defer srv.Close()

	cfg.EnrichWith = []string{"mfa"}
	p := NewWithClient(cfg, srv.Client())
	store := newTestStore()
	docs := collectDocs(context.Background(), t, p, store, true)

	if len(docs) != 2 {
		t.Fatalf("got %d docs; want 2", len(docs))
	}

	sort.Slice(docs, func(i, j int) bool { return docs[i].ID < docs[j].ID })

	mfaData, ok := docs[0].Fields["user.risk.mfa"].(*MFADetails)
	if !ok {
		t.Fatalf("u1 user.risk.mfa is %T; want *MFADetails", docs[0].Fields["user.risk.mfa"])
	}
	if !mfaData.IsMFACapable {
		t.Error("u1 should be MFA capable")
	}
	if !mfaData.IsMFARegistered {
		t.Error("u1 should be MFA registered")
	}

	if _, ok := docs[1].Fields["user.risk.mfa"]; ok {
		t.Error("u2 should have no MFA data")
	}
}

func TestPublisherError_StopsSync(t *testing.T) {
	srv, cfg := startTestGraph(t, testGraphOpts{
		fullUsers: []json.RawMessage{
			rawUser("u1", nil),
			rawUser("u2", nil),
		},
		fullDevices:  []json.RawMessage{},
		groups:       []Group{},
		groupMembers: map[string][]Member{},
		deviceOwners: map[string][]map[string]any{},
		deviceUsers:  map[string][]map[string]any{},
	})
	defer srv.Close()

	p := NewWithClient(cfg, srv.Client())
	store := newTestStore()

	pubErr := errors.New("pipeline full")
	pub := func(_ context.Context, doc entcollect.Document) error {
		return pubErr
	}

	err := p.FullSync(context.Background(), store, pub, slog.Default())
	if !errors.Is(err, pubErr) {
		t.Errorf("error = %v; want pipeline full", err)
	}
}

// --- helpers (callees after callers) ---

func collectDocs(ctx context.Context, t *testing.T, p *Provider, store entcollect.Store, fullSync bool) []entcollect.Document {
	t.Helper()
	var docs []entcollect.Document
	pub := func(_ context.Context, doc entcollect.Document) error {
		docs = append(docs, doc)
		return nil
	}
	var err error
	if fullSync {
		err = p.FullSync(ctx, store, pub, slog.Default())
	} else {
		err = p.IncrementalSync(ctx, store, pub, slog.Default())
	}
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	return docs
}

func startTestGraph(t *testing.T, opts testGraphOpts) (*httptest.Server, Config) {
	t.Helper()
	var srvURL string
	mux := testGraphMux(t, opts, &srvURL)
	srv := httptest.NewServer(mux)
	srvURL = srv.URL
	cfg := DefaultConfig()
	cfg.TenantID = "tenant-1"
	cfg.ClientID = "client-1"
	cfg.ClientSecret = "secret-1"
	cfg.LoginEndpoint = srv.URL
	cfg.APIEndpoint = srv.URL + "/v1.0"
	return srv, cfg
}

func rawUser(id string, fields map[string]any) json.RawMessage {
	m := map[string]any{"id": id}
	for k, v := range fields {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return b
}

func rawRemovedUser(id string) json.RawMessage {
	m := map[string]any{
		"id":       id,
		"@removed": map[string]any{"reason": "deleted"},
	}
	b, _ := json.Marshal(m)
	return b
}

func rawDevice(id string, fields map[string]any) json.RawMessage {
	m := map[string]any{"id": id}
	for k, v := range fields {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return b
}

type testGraphOpts struct {
	fullUsers    []json.RawMessage
	deltaUsers   []json.RawMessage
	fullDevices  []json.RawMessage
	deltaDevices []json.RawMessage

	alwaysFullUsers   bool
	alwaysFullDevices bool

	groups       []Group
	groupMembers map[string][]Member

	deviceOwners map[string][]map[string]any
	deviceUsers  map[string][]map[string]any

	mfaResponse any
}

func testGraphMux(t *testing.T, opts testGraphOpts, srvURL *string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()

	deltaLink := func(path string) string {
		return *srvURL + path
	}

	mux.HandleFunc("POST /tenant-1/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(authTokenResponse{
			AccessToken: "test-token",
			TokenType:   "Bearer",
			ExpiresIn:   3600,
		})
	})

	var userDeltaCalls atomic.Int32
	mux.HandleFunc("GET /v1.0/users/delta", func(w http.ResponseWriter, r *http.Request) {
		n := userDeltaCalls.Add(1)
		var resp deltaResponse[json.RawMessage]
		if n == 1 || opts.alwaysFullUsers {
			resp.Value = opts.fullUsers
			resp.DeltaLink = deltaLink("/v1.0/users/delta?$deltatoken=full")
		} else {
			resp.Value = opts.deltaUsers
			resp.DeltaLink = deltaLink("/v1.0/users/delta?$deltatoken=incr")
		}
		json.NewEncoder(w).Encode(resp)
	})

	var deviceDeltaCalls atomic.Int32
	mux.HandleFunc("GET /v1.0/devices/delta", func(w http.ResponseWriter, r *http.Request) {
		n := deviceDeltaCalls.Add(1)
		var resp deltaResponse[json.RawMessage]
		if n == 1 || opts.alwaysFullDevices {
			resp.Value = opts.fullDevices
			resp.DeltaLink = deltaLink("/v1.0/devices/delta?$deltatoken=full")
		} else {
			resp.Value = opts.deltaDevices
			resp.DeltaLink = deltaLink("/v1.0/devices/delta?$deltatoken=incr")
		}
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("GET /v1.0/groups", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(deltaResponse[Group]{Value: opts.groups})
	})

	mux.HandleFunc("GET /v1.0/groups/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 5 || parts[4] != "members" {
			http.NotFound(w, r)
			return
		}
		groupID := parts[3]
		members := opts.groupMembers[groupID]
		json.NewEncoder(w).Encode(deltaResponse[Member]{Value: members})
	})

	mux.HandleFunc("GET /v1.0/devices/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 5 {
			http.NotFound(w, r)
			return
		}
		deviceID := parts[3]
		relation := parts[4]
		var data []map[string]any
		switch relation {
		case "registeredOwners":
			data = opts.deviceOwners[deviceID]
		case "registeredUsers":
			data = opts.deviceUsers[deviceID]
		}
		json.NewEncoder(w).Encode(deltaResponse[map[string]any]{Value: data})
	})

	mux.HandleFunc("GET /v1.0/reports/authenticationMethods/userRegistrationDetails", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(opts.mfaResponse)
	})

	return mux
}

type testStore struct {
	data map[string][]byte
}

func newTestStore() *testStore {
	return &testStore{data: make(map[string][]byte)}
}

func (s *testStore) Get(key string, dst any) error {
	b, ok := s.data[key]
	if !ok {
		return entcollect.ErrKeyNotFound
	}
	return json.Unmarshal(b, dst)
}

func (s *testStore) Set(key string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	s.data[key] = b
	return nil
}

func (s *testStore) Delete(key string) error {
	delete(s.data, key)
	return nil
}

func (s *testStore) Each(fn func(key string, decode func(any) error) (bool, error)) error {
	for k, v := range s.data {
		ok, err := fn(k, func(dst any) error {
			return json.Unmarshal(v, dst)
		})
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
	}
	return nil
}

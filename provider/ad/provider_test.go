// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ad_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimlambrt/gldap"

	"github.com/elastic/entcollect"
	"github.com/elastic/entcollect/provider/ad"
)

func TestFullSync_UsersAndDevices(t *testing.T) {
	fix := &ldapFixture{
		users: []ldapEntry{
			{
				dn: "cn=alice,dc=example,dc=com",
				attrs: map[string][]string{
					"cn":                {"alice"},
					"distinguishedName": {"cn=alice,dc=example,dc=com"},
					"whenChanged":       {"20260101120000.0Z"},
				},
			},
			{
				dn: "cn=bob,dc=example,dc=com",
				attrs: map[string][]string{
					"cn":                {"bob"},
					"distinguishedName": {"cn=bob,dc=example,dc=com"},
					"whenChanged":       {"20260101130000.0Z"},
				},
			},
		},
		devices: []ldapEntry{
			{
				dn: "cn=host1,dc=example,dc=com",
				attrs: map[string][]string{
					"cn":                {"host1"},
					"distinguishedName": {"cn=host1,dc=example,dc=com"},
					"whenChanged":       {"20260101140000.0Z"},
				},
			},
		},
	}

	url := startTestLDAPServer(t, fix)
	p := newTestProvider(t, url)
	store := newMemStore()

	docs := collectDocs(t.Context(), t, p, store, true)

	userDocs := filterByKind(docs, entcollect.KindUser)
	deviceDocs := filterByKind(docs, entcollect.KindDevice)

	if len(userDocs) != 2 {
		t.Fatalf("got %d user docs; want 2", len(userDocs))
	}
	if len(deviceDocs) != 1 {
		t.Fatalf("got %d device docs; want 1", len(deviceDocs))
	}

	for _, doc := range userDocs {
		if doc.Action != entcollect.ActionDiscovered {
			t.Errorf("user %s Action = %v; want ActionDiscovered", doc.ID, doc.Action)
		}
		if doc.Fields["user.id"] != doc.ID {
			t.Errorf("user %s user.id = %v; want %s", doc.ID, doc.Fields["user.id"], doc.ID)
		}
	}

	for _, doc := range deviceDocs {
		if doc.Action != entcollect.ActionDiscovered {
			t.Errorf("device %s Action = %v; want ActionDiscovered", doc.ID, doc.Action)
		}
		if doc.Fields["device.id"] != doc.ID {
			t.Errorf("device %s device.id = %v; want %s", doc.ID, doc.Fields["device.id"], doc.ID)
		}
	}

	// Cursor should be written.
	var cursor time.Time
	if err := store.Get("ad.cursor.when_changed", &cursor); err != nil {
		t.Errorf("get cursor: %v", err)
	}
	if cursor.IsZero() {
		t.Error("cursor is zero")
	}
}

func TestFullSync_SubsequentRun(t *testing.T) {
	fix := &ldapFixture{
		users: []ldapEntry{
			{
				dn: "cn=alice,dc=example,dc=com",
				attrs: map[string][]string{
					"cn":                {"alice"},
					"distinguishedName": {"cn=alice,dc=example,dc=com"},
					"whenChanged":       {"20260101120000.0Z"},
				},
			},
		},
	}

	url := startTestLDAPServer(t, fix)
	p := newTestProvider(t, url)
	store := newMemStore()

	// First run: discovered.
	collectDocs(t.Context(), t, p, store, true)

	// Second run: same entity — modified.
	docs := collectDocs(t.Context(), t, p, store, true)
	userDocs := filterByKind(docs, entcollect.KindUser)
	if len(userDocs) != 1 {
		t.Fatalf("got %d user docs; want 1", len(userDocs))
	}
	if userDocs[0].Action != entcollect.ActionModified {
		t.Errorf("Action = %v; want ActionModified", userDocs[0].Action)
	}
}

func TestFullSync_DeletionDetection(t *testing.T) {
	fix := &ldapFixture{
		users: []ldapEntry{
			{
				dn: "cn=alice,dc=example,dc=com",
				attrs: map[string][]string{
					"cn":                {"alice"},
					"distinguishedName": {"cn=alice,dc=example,dc=com"},
					"whenChanged":       {"20260101120000.0Z"},
				},
			},
			{
				dn: "cn=bob,dc=example,dc=com",
				attrs: map[string][]string{
					"cn":                {"bob"},
					"distinguishedName": {"cn=bob,dc=example,dc=com"},
					"whenChanged":       {"20260101130000.0Z"},
				},
			},
		},
	}

	url := startTestLDAPServer(t, fix)
	p := newTestProvider(t, url)
	store := newMemStore()

	// Run 1: both users present.
	collectDocs(t.Context(), t, p, store, true)

	// Run 2: bob disappears.
	fix.users = fix.users[:1]
	docs := collectDocs(t.Context(), t, p, store, true)

	actions := make(map[string]entcollect.Action)
	for _, d := range docs {
		if d.Kind == entcollect.KindUser {
			actions[d.ID] = d.Action
		}
	}

	if actions["cn=alice,dc=example,dc=com"] != entcollect.ActionModified {
		t.Errorf("alice Action = %v; want ActionModified", actions["cn=alice,dc=example,dc=com"])
	}
	if actions["cn=bob,dc=example,dc=com"] != entcollect.ActionDeleted {
		t.Errorf("bob Action = %v; want ActionDeleted", actions["cn=bob,dc=example,dc=com"])
	}
}

func TestFullSync_DatasetUsers(t *testing.T) {
	fix := &ldapFixture{
		users: []ldapEntry{
			{
				dn: "cn=alice,dc=example,dc=com",
				attrs: map[string][]string{
					"cn":                {"alice"},
					"distinguishedName": {"cn=alice,dc=example,dc=com"},
					"whenChanged":       {"20260101120000.0Z"},
				},
			},
		},
		devices: []ldapEntry{
			{
				dn: "cn=host1,dc=example,dc=com",
				attrs: map[string][]string{
					"cn":                {"host1"},
					"distinguishedName": {"cn=host1,dc=example,dc=com"},
					"whenChanged":       {"20260101140000.0Z"},
				},
			},
		},
	}

	url := startTestLDAPServer(t, fix)

	cfg := ad.DefaultConfig()
	cfg.URL = url
	cfg.BaseDN = "DC=example,DC=com"
	cfg.User = "cn=admin,dc=example,dc=com"
	cfg.Password = "pass"
	cfg.Dataset = "users"
	p, err := ad.New(cfg)
	if err != nil {
		t.Fatalf("ad.New: %v", err)
	}

	store := newMemStore()
	docs := collectDocs(t.Context(), t, p, store, true)

	if deviceDocs := filterByKind(docs, entcollect.KindDevice); len(deviceDocs) != 0 {
		t.Errorf("got %d device docs with dataset=users; want 0", len(deviceDocs))
	}
	if userDocs := filterByKind(docs, entcollect.KindUser); len(userDocs) != 1 {
		t.Errorf("got %d user docs with dataset=users; want 1", len(userDocs))
	}
}

func TestFullSync_DatasetDevices(t *testing.T) {
	fix := &ldapFixture{
		users: []ldapEntry{
			{
				dn: "cn=alice,dc=example,dc=com",
				attrs: map[string][]string{
					"cn":                {"alice"},
					"distinguishedName": {"cn=alice,dc=example,dc=com"},
					"whenChanged":       {"20260101120000.0Z"},
				},
			},
		},
		devices: []ldapEntry{
			{
				dn: "cn=host1,dc=example,dc=com",
				attrs: map[string][]string{
					"cn":                {"host1"},
					"distinguishedName": {"cn=host1,dc=example,dc=com"},
					"whenChanged":       {"20260101140000.0Z"},
				},
			},
		},
	}

	url := startTestLDAPServer(t, fix)

	cfg := ad.DefaultConfig()
	cfg.URL = url
	cfg.BaseDN = "DC=example,DC=com"
	cfg.User = "cn=admin,dc=example,dc=com"
	cfg.Password = "pass"
	cfg.Dataset = "devices"
	p, err := ad.New(cfg)
	if err != nil {
		t.Fatalf("ad.New: %v", err)
	}

	store := newMemStore()
	docs := collectDocs(t.Context(), t, p, store, true)

	if userDocs := filterByKind(docs, entcollect.KindUser); len(userDocs) != 0 {
		t.Errorf("got %d user docs with dataset=devices; want 0", len(userDocs))
	}
	if deviceDocs := filterByKind(docs, entcollect.KindDevice); len(deviceDocs) != 1 {
		t.Errorf("got %d device docs with dataset=devices; want 1", len(deviceDocs))
	}
}

func TestFullSync_EmptyGroups(t *testing.T) {
	fix := &ldapFixture{
		users: []ldapEntry{
			{
				dn: "cn=alice,dc=example,dc=com",
				attrs: map[string][]string{
					"cn":                {"alice"},
					"distinguishedName": {"cn=alice,dc=example,dc=com"},
					"whenChanged":       {"20260101120000.0Z"},
				},
			},
		},
		groups: []ldapEntry{
			{
				dn: "cn=Empty Group,dc=example,dc=com",
				attrs: map[string][]string{
					"cn":                {"Empty Group"},
					"distinguishedName": {"cn=Empty Group,dc=example,dc=com"},
					"whenChanged":       {"20260101100000.0Z"},
				},
			},
		},
	}

	url := startTestLDAPServer(t, fix)

	cfg := ad.DefaultConfig()
	cfg.URL = url
	cfg.BaseDN = "DC=example,DC=com"
	cfg.User = "cn=admin,dc=example,dc=com"
	cfg.Password = "pass"
	cfg.IncludeEmptyGroups = true
	p, err := ad.New(cfg)
	if err != nil {
		t.Fatalf("ad.New: %v", err)
	}

	store := newMemStore()
	docs := collectDocs(t.Context(), t, p, store, true)

	groupDocs := filterByKind(docs, entcollect.KindGroup)
	if len(groupDocs) != 1 {
		t.Fatalf("got %d group docs; want 1", len(groupDocs))
	}
	if groupDocs[0].Fields["group.id"] != "cn=Empty Group,dc=example,dc=com" {
		t.Errorf("group.id = %v; want cn=Empty Group,dc=example,dc=com", groupDocs[0].Fields["group.id"])
	}
}

func TestFullSync_DatasetChangeNoSpuriousDeletions(t *testing.T) {
	fix := &ldapFixture{
		users: []ldapEntry{
			{
				dn: "cn=alice,dc=example,dc=com",
				attrs: map[string][]string{
					"cn":                {"alice"},
					"distinguishedName": {"cn=alice,dc=example,dc=com"},
					"whenChanged":       {"20260101120000.0Z"},
				},
			},
		},
		devices: []ldapEntry{
			{
				dn: "cn=host1,dc=example,dc=com",
				attrs: map[string][]string{
					"cn":                {"host1"},
					"distinguishedName": {"cn=host1,dc=example,dc=com"},
					"whenChanged":       {"20260101140000.0Z"},
				},
			},
		},
	}

	url := startTestLDAPServer(t, fix)
	store := newMemStore()

	// Run 1: sync both users and devices (dataset=all).
	p := newTestProvider(t, url)
	collectDocs(t.Context(), t, p, store, true)

	// Run 2: narrow to dataset=users only. Devices should not be
	// emitted as deleted since the provider is no longer tracking them.
	cfg := ad.DefaultConfig()
	cfg.URL = url
	cfg.BaseDN = "DC=example,DC=com"
	cfg.User = "cn=admin,dc=example,dc=com"
	cfg.Password = "pass"
	cfg.Dataset = "users"
	pUsers, err := ad.New(cfg)
	if err != nil {
		t.Fatalf("ad.New: %v", err)
	}

	docs := collectDocs(t.Context(), t, pUsers, store, true)

	for _, doc := range docs {
		if doc.Kind == entcollect.KindDevice {
			t.Errorf("unexpected device doc %s with action %v; dataset=users should not touch devices", doc.ID, doc.Action)
		}
	}
}

func TestIncrementalSync_NoCursorUsesZero(t *testing.T) {
	fix := &ldapFixture{
		users: []ldapEntry{
			{
				dn: "cn=alice,dc=example,dc=com",
				attrs: map[string][]string{
					"cn":                {"alice"},
					"distinguishedName": {"cn=alice,dc=example,dc=com"},
					"whenChanged":       {"20260101120000.0Z"},
				},
			},
		},
	}

	url := startTestLDAPServer(t, fix)
	p := newTestProvider(t, url)
	store := newMemStore()

	// Incremental with no prior cursor should still fetch.
	docs := collectDocs(t.Context(), t, p, store, false)
	if len(docs) != 1 {
		t.Fatalf("got %d docs; want 1", len(docs))
	}

	// Cursor should be written using the update key.
	var cursor time.Time
	if err := store.Get("ad.cursor.when_changed", &cursor); err != nil {
		t.Errorf("get cursor: %v", err)
	}
}

func TestIncrementalSync_NoIdsetSideEffects(t *testing.T) {
	fix := &ldapFixture{
		users: []ldapEntry{
			{
				dn: "cn=alice,dc=example,dc=com",
				attrs: map[string][]string{
					"cn":                {"alice"},
					"distinguishedName": {"cn=alice,dc=example,dc=com"},
					"whenChanged":       {"20260101120000.0Z"},
				},
			},
			{
				dn: "cn=bob,dc=example,dc=com",
				attrs: map[string][]string{
					"cn":                {"bob"},
					"distinguishedName": {"cn=bob,dc=example,dc=com"},
					"whenChanged":       {"20260101130000.0Z"},
				},
			},
		},
	}

	url := startTestLDAPServer(t, fix)
	p := newTestProvider(t, url)
	store := newMemStore()

	// Full sync: establish idsets with both users.
	collectDocs(t.Context(), t, p, store, true)

	// Incremental sync: only alice returned (simulating bob unchanged).
	fix.users = fix.users[:1]
	collectDocs(t.Context(), t, p, store, false)

	// Next full sync: bob disappears for real.
	// If incremental sync had corrupted the idset, bob would not be
	// detected as missing. Restore fixture for full sync to see both
	// initially, then remove bob.
	fix.users = []ldapEntry{
		{
			dn: "cn=alice,dc=example,dc=com",
			attrs: map[string][]string{
				"cn":                {"alice"},
				"distinguishedName": {"cn=alice,dc=example,dc=com"},
				"whenChanged":       {"20260101120000.0Z"},
			},
		},
	}
	docs := collectDocs(t.Context(), t, p, store, true)

	actions := make(map[string]entcollect.Action)
	for _, d := range docs {
		if d.Kind == entcollect.KindUser {
			actions[d.ID] = d.Action
		}
	}

	if actions["cn=bob,dc=example,dc=com"] != entcollect.ActionDeleted {
		t.Errorf("bob Action = %v after full sync; want ActionDeleted (incremental must not corrupt idset)", actions["cn=bob,dc=example,dc=com"])
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*ad.Config)
		wantErr string
	}{
		{"missing URL", func(c *ad.Config) { c.URL = "" }, "ad_url is required"},
		{"missing BaseDN", func(c *ad.Config) { c.BaseDN = "" }, "ad_base_dn is required"},
		{"missing User", func(c *ad.Config) { c.User = "" }, "ad_user is required"},
		{"missing Password", func(c *ad.Config) { c.Password = "" }, "ad_password is required"},
		{"bad dataset", func(c *ad.Config) { c.Dataset = "invalid" }, "dataset must be"},
		{"bad sync interval", func(c *ad.Config) { c.SyncInterval = 0 }, "sync_interval must be positive"},
		{"bad update interval", func(c *ad.Config) { c.UpdateInterval = 0 }, "update_interval must be positive"},
		{"sync <= update", func(c *ad.Config) { c.SyncInterval = time.Minute; c.UpdateInterval = time.Minute }, "sync_interval must be greater"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := ad.DefaultConfig()
			cfg.URL = "ldap://localhost"
			cfg.BaseDN = "DC=example,DC=com"
			cfg.User = "admin"
			cfg.Password = "pass"
			test.modify(&cfg)

			err := cfg.Validate()
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("error = %q; want containing %q", err.Error(), test.wantErr)
			}
		})
	}
}

func TestFullSync_ConfiguredAttrsHaveIDsAndCursor(t *testing.T) {
	fix := &ldapFixture{
		users: []ldapEntry{
			{
				dn: "cn=alice,dc=example,dc=com",
				attrs: map[string][]string{
					"cn":                {"alice"},
					"distinguishedName": {"cn=alice,dc=example,dc=com"},
					"mail":              {"alice@example.com"},
					"whenChanged":       {"20260101120000.0Z"},
				},
			},
		},
	}

	url := startTestLDAPServer(t, fix)

	cfg := ad.DefaultConfig()
	cfg.URL = url
	cfg.BaseDN = "DC=example,DC=com"
	cfg.User = "cn=admin,dc=example,dc=com"
	cfg.Password = "pass"
	cfg.Dataset = "users"
	cfg.UserAttrs = []string{"cn", "mail"}

	p, err := ad.New(cfg)
	if err != nil {
		t.Fatalf("ad.New: %v", err)
	}

	store := newMemStore()
	docs := collectDocs(t.Context(), t, p, store, true)
	if len(docs) == 0 {
		t.Fatal("expected at least one document")
	}
	for _, doc := range docs {
		if doc.ID == "" {
			t.Error("document has empty ID; distinguishedName should be mandatory")
		}
	}

	var cursor time.Time
	if err := store.Get("ad.cursor.when_changed", &cursor); err != nil {
		t.Fatalf("cursor not written: %v", err)
	}
	if cursor.IsZero() {
		t.Error("cursor is zero; whenChanged should be mandatory")
	}
}

func collectDocs(ctx context.Context, t *testing.T, p *ad.Provider, store entcollect.Store, full bool) []entcollect.Document {
	t.Helper()
	var docs []entcollect.Document
	pub := func(_ context.Context, doc entcollect.Document) error {
		docs = append(docs, doc)
		return nil
	}
	log := slog.New(slog.NewTextHandler(&testLogWriter{t}, nil))

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

func newTestProvider(t *testing.T, url string) *ad.Provider {
	t.Helper()
	cfg := ad.DefaultConfig()
	cfg.URL = url
	cfg.BaseDN = "DC=example,DC=com"
	cfg.User = "cn=admin,dc=example,dc=com"
	cfg.Password = "pass"
	p, err := ad.New(cfg)
	if err != nil {
		t.Fatalf("ad.New: %v", err)
	}
	return p
}

func filterByKind(docs []entcollect.Document, kind entcollect.EntityKind) []entcollect.Document {
	var out []entcollect.Document
	for _, d := range docs {
		if d.Kind == kind {
			out = append(out, d)
		}
	}
	return out
}

// startTestLDAPServer is the common-case wrapper for startLDAPServer that
// discards the testLDAPServer handle. Benchmarks that need to count LDAP
// searches use startLDAPServer directly.
func startTestLDAPServer(t *testing.T, fix *ldapFixture) string {
	_, url := startLDAPServer(t, fix)
	return url
}

// startLDAPServer starts a gldap server on a free port using the provided
// fixture data. It returns the server handle (for search counting) and the
// ldap:// URL to connect to.
func startLDAPServer(tb testing.TB, fix *ldapFixture) (*testLDAPServer, string) {
	tb.Helper()

	ts := &testLDAPServer{fix: fix}

	s, err := gldap.NewServer()
	if err != nil {
		tb.Fatalf("gldap new server: %v", err)
	}
	tb.Cleanup(func() { _ = s.Stop() })

	mux, err := gldap.NewMux()
	if err != nil {
		tb.Fatalf("gldap new mux: %v", err)
	}

	err = mux.Bind(func(w *gldap.ResponseWriter, r *gldap.Request) {
		resp := r.NewBindResponse()
		resp.SetResultCode(gldap.ResultSuccess)
		_ = w.Write(resp)
	})
	if err != nil {
		tb.Fatalf("mux bind: %v", err)
	}

	err = mux.Search(ts.searchHandler(tb))
	if err != nil {
		tb.Fatalf("mux search: %v", err)
	}

	err = mux.Unbind(func(w *gldap.ResponseWriter, r *gldap.Request) {})
	if err != nil {
		tb.Fatalf("mux unbind: %v", err)
	}

	err = s.Router(mux)
	if err != nil {
		tb.Fatalf("gldap router: %v", err)
	}

	// Find a free port.
	var lc net.ListenConfig
	ln, err := lc.Listen(tb.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	go func() {
		_ = s.Run(addr)
	}()
	// Wait for server to be ready.
	for i := 0; i < 100; i++ {
		if s.Ready() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !s.Ready() {
		tb.Fatal("gldap server not ready")
	}

	return ts, "ldap://" + addr
}

func appendUnique(entries []ldapEntry, e ldapEntry) []ldapEntry {
	for _, existing := range entries {
		if existing.dn == e.dn {
			return entries
		}
	}
	return append(entries, e)
}

// testLDAPServer holds a running gldap server and its fixture data. The
// fixture is a pointer so tests can mutate it between sync calls.
type testLDAPServer struct {
	fix      *ldapFixture
	searches atomic.Int64
}

func (s *testLDAPServer) resetSearches()     { s.searches.Store(0) }
func (s *testLDAPServer) searchCount() int64 { return s.searches.Load() }

// ldapFixture describes the entries the test LDAP server should return.
type ldapFixture struct {
	users   []ldapEntry
	devices []ldapEntry
	groups  []ldapEntry
}

type ldapEntry struct {
	dn    string
	attrs map[string][]string
}

func (s *testLDAPServer) searchHandler(t testing.TB) gldap.HandlerFunc {
	t.Helper()
	return func(w *gldap.ResponseWriter, r *gldap.Request) {
		s.searches.Add(1)

		msg, err := r.GetSearchMessage()
		if err != nil {
			t.Errorf("get search message: %v", err)
			return
		}

		filter := msg.Filter
		fix := s.fix

		var results []ldapEntry

		switch {
		case strings.Contains(filter, "objectClass=group") && strings.Contains(filter, "!(member="):
			results = fix.groups
		case strings.Contains(filter, "objectClass=group"):
			for _, g := range fix.groups {
				results = appendUnique(results, g)
			}
		case strings.Contains(filter, "objectClass=computer"):
			results = fix.devices
		case strings.Contains(filter, "objectCategory=person"):
			results = fix.users
		default:
			t.Logf("unhandled filter: %s", filter)
		}

		for _, entry := range results {
			e := r.NewSearchResponseEntry(entry.dn)
			for name, vals := range entry.attrs {
				e.AddAttribute(name, vals)
			}
			_ = w.Write(e)
		}

		done := r.NewSearchDoneResponse()
		done.SetResultCode(gldap.ResultSuccess)
		_ = w.Write(done)
	}
}

// memStore is a minimal in-memory entcollect.Store.
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

type testLogWriter struct{ t *testing.T }

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

func BenchmarkADFullSync(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("entities=%d", n), func(b *testing.B) {
			fix := &ldapFixture{
				users:   generateLDAPEntries(n, "user"),
				devices: generateLDAPEntries(n/2, "host"),
			}
			ts, url := startLDAPServer(b, fix)
			p := newBenchProvider(b, url)

			log := slog.New(slog.NewTextHandler(&noopWriter{}, nil))
			ctx := context.Background()

			b.ReportAllocs()
			ts.resetSearches()
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
			b.ReportMetric(float64(ts.searchCount())/float64(b.N), "ldap-searches/op")
			if len(lastDocs) > 0 {
				total := docFieldsBytes(lastDocs)
				b.ReportMetric(float64(total)/float64(len(lastDocs)), "bytes/doc")
			}
		})
	}
}

func BenchmarkADIncrementalSync(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("entities=%d", n), func(b *testing.B) {
			fix := &ldapFixture{
				users:   generateLDAPEntries(n, "user"),
				devices: generateLDAPEntries(n/2, "host"),
			}
			ts, url := startLDAPServer(b, fix)
			p := newBenchProvider(b, url)

			log := slog.New(slog.NewTextHandler(&noopWriter{}, nil))
			ctx := context.Background()

			b.ReportAllocs()
			ts.resetSearches()
			b.ResetTimer()
			var lastDocs []entcollect.Document
			for range b.N {
				store := newMemStore()
				lastDocs = lastDocs[:0]
				pub := func(_ context.Context, doc entcollect.Document) error {
					lastDocs = append(lastDocs, doc)
					return nil
				}
				err := p.IncrementalSync(ctx, store, pub, log)
				if err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(ts.searchCount())/float64(b.N), "ldap-searches/op")
			if len(lastDocs) > 0 {
				total := docFieldsBytes(lastDocs)
				b.ReportMetric(float64(total)/float64(len(lastDocs)), "bytes/doc")
			}
		})
	}
}

func generateLDAPEntries(n int, kind string) []ldapEntry {
	entries := make([]ldapEntry, n)
	for i := range n {
		cn := fmt.Sprintf("%s-%06d", kind, i)
		dn := fmt.Sprintf("cn=%s,dc=example,dc=com", cn)
		entries[i] = ldapEntry{
			dn: dn,
			attrs: map[string][]string{
				"cn":                {cn},
				"distinguishedName": {dn},
				"whenChanged":       {"20260101120000.0Z"},
			},
		}
	}
	return entries
}

func newBenchProvider(b *testing.B, url string) *ad.Provider {
	b.Helper()
	cfg := ad.DefaultConfig()
	cfg.URL = url
	cfg.BaseDN = "DC=example,DC=com"
	cfg.User = "cn=admin,dc=example,dc=com"
	cfg.Password = "pass"
	p, err := ad.New(cfg)
	if err != nil {
		b.Fatalf("ad.New: %v", err)
	}
	return p
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

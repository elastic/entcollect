// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package jamf_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elastic/entcollect"
	"github.com/elastic/entcollect/provider/jamf"
)

func TestFullSync_FirstRun(t *testing.T) {
	managed := boolPtr(true)
	fs := &fakeServer{
		computers: []jamf.Computer{
			{UDID: strPtr("aaa"), Name: strPtr("host-a"), IsManaged: managed},
			{UDID: strPtr("bbb"), Name: strPtr("host-b"), IsManaged: managed},
		},
	}
	p, _, _ := newTestProvider(t, fs)
	store := newMemStore()

	docs := collectDocs(t.Context(), t, p, store, true)

	if len(docs) != 2 {
		t.Fatalf("got %d docs; want 2", len(docs))
	}
	for _, doc := range docs {
		if doc.Kind != entcollect.KindDevice {
			t.Errorf("doc %s Kind = %v; want KindDevice", doc.ID, doc.Kind)
		}
		if doc.Action != entcollect.ActionDiscovered {
			t.Errorf("doc %s Action = %v; want ActionDiscovered", doc.ID, doc.Action)
		}
		if doc.Fields["device.id"] != doc.ID {
			t.Errorf("doc %s device.id = %v; want %s", doc.ID, doc.Fields["device.id"], doc.ID)
		}
		if _, ok := doc.Fields["jamf"]; !ok {
			t.Errorf("doc %s missing jamf field", doc.ID)
		}
	}

	// Cursor must be written.
	var cursor time.Time
	if err := store.Get("jamf.cursor.last_sync", &cursor); err != nil {
		t.Errorf("get cursor: %v", err)
	}
	if cursor.IsZero() {
		t.Errorf("cursor is zero")
	}
}

func TestFullSync_SubsequentRun(t *testing.T) {
	managed := boolPtr(true)
	fs := &fakeServer{
		computers: []jamf.Computer{
			{UDID: strPtr("aaa"), Name: strPtr("host-a"), IsManaged: managed},
		},
	}
	p, _, _ := newTestProvider(t, fs)
	store := newMemStore()

	// First run establishes the IDset.
	collectDocs(t.Context(), t, p, store, true)

	// Second run: same device — should be Modified.
	docs := collectDocs(t.Context(), t, p, store, true)
	if len(docs) != 1 {
		t.Fatalf("got %d docs; want 1", len(docs))
	}
	if docs[0].Action != entcollect.ActionModified {
		t.Errorf("Action = %v; want ActionModified", docs[0].Action)
	}
}

func TestFullSync_UnmanagedDevice(t *testing.T) {
	unmanaged := boolPtr(false)
	fs := &fakeServer{
		computers: []jamf.Computer{
			{UDID: strPtr("aaa"), Name: strPtr("host-a"), IsManaged: unmanaged},
		},
	}
	p, _, _ := newTestProvider(t, fs)
	store := newMemStore()

	docs := collectDocs(t.Context(), t, p, store, true)
	if len(docs) != 1 {
		t.Fatalf("got %d docs; want 1", len(docs))
	}
	if docs[0].Action != entcollect.ActionDeleted {
		t.Errorf("Action = %v; want ActionDeleted", docs[0].Action)
	}
}

func TestFullSync_NilIsManaged(t *testing.T) {
	fs := &fakeServer{
		computers: []jamf.Computer{
			{UDID: strPtr("aaa"), Name: strPtr("host-a"), IsManaged: nil},
		},
	}
	p, _, _ := newTestProvider(t, fs)
	store := newMemStore()

	docs := collectDocs(t.Context(), t, p, store, true)
	if len(docs) != 1 {
		t.Fatalf("got %d docs; want 1", len(docs))
	}
	if docs[0].Action != entcollect.ActionDeleted {
		t.Errorf("Action = %v; want ActionDeleted (nil IsManaged must be treated as unmanaged)", docs[0].Action)
	}
}

func TestFullSync_AbsenceDeletion(t *testing.T) {
	managed := boolPtr(true)
	fs := &fakeServer{
		computers: []jamf.Computer{
			{UDID: strPtr("aaa"), Name: strPtr("host-a"), IsManaged: managed},
			{UDID: strPtr("bbb"), Name: strPtr("host-b"), IsManaged: managed},
		},
	}
	p, _, _ := newTestProvider(t, fs)
	store := newMemStore()

	// Run 1: establish both devices in IDset.
	collectDocs(t.Context(), t, p, store, true)

	// Run 2: host-b disappears from API response.
	fs.computers = []jamf.Computer{
		{UDID: strPtr("aaa"), Name: strPtr("host-a"), IsManaged: managed},
	}

	docs := collectDocs(t.Context(), t, p, store, true)

	ids := make(map[string]entcollect.Action, len(docs))
	for _, d := range docs {
		ids[d.ID] = d.Action
	}

	if ids["aaa"] != entcollect.ActionModified {
		t.Errorf("aaa Action = %v; want ActionModified", ids["aaa"])
	}
	if ids["bbb"] != entcollect.ActionDeleted {
		t.Errorf("bbb Action = %v; want ActionDeleted (absent from API)", ids["bbb"])
	}
}

func TestFullSync_Pagination(t *testing.T) {
	managed := boolPtr(true)
	computers := make([]jamf.Computer, 5)
	for i := range computers {
		udid := fmt.Sprintf("dev-%02d", i)
		computers[i] = jamf.Computer{UDID: strPtr(udid), IsManaged: managed}
	}

	fs := &fakeServer{computers: computers, pageSize: 2}
	p, _, _ := newTestProvider(t, fs)
	store := newMemStore()

	docs := collectDocs(t.Context(), t, p, store, true)
	if len(docs) != 5 {
		t.Fatalf("got %d docs; want 5", len(docs))
	}

	var ids []string
	for _, d := range docs {
		ids = append(ids, d.ID)
	}
	slices.Sort(ids)
	for i, want := range []string{"dev-00", "dev-01", "dev-02", "dev-03", "dev-04"} {
		if ids[i] != want {
			t.Errorf("ids[%d] = %q; want %q", i, ids[i], want)
		}
	}
}

func TestIncrementalSync_CursorKey(t *testing.T) {
	managed := boolPtr(true)
	fs := &fakeServer{
		computers: []jamf.Computer{
			{UDID: strPtr("aaa"), IsManaged: managed},
		},
	}
	p, _, _ := newTestProvider(t, fs)
	store := newMemStore()

	collectDocs(t.Context(), t, p, store, false)

	var cursor time.Time
	if err := store.Get("jamf.cursor.last_update", &cursor); err != nil {
		t.Errorf("get last_update cursor: %v", err)
	}
	if cursor.IsZero() {
		t.Errorf("last_update cursor is zero")
	}

	// FullSync cursor must NOT be set.
	var syncCursor time.Time
	if err := store.Get("jamf.cursor.last_sync", &syncCursor); err == nil {
		t.Errorf("last_sync cursor unexpectedly set by IncrementalSync")
	}
}

func TestFullSync_MissingUDID(t *testing.T) {
	managed := boolPtr(true)
	fs := &fakeServer{
		computers: []jamf.Computer{
			{UDID: nil, Name: strPtr("no-udid"), IsManaged: managed},
			{UDID: strPtr("bbb"), Name: strPtr("host-b"), IsManaged: managed},
		},
	}
	p, _, _ := newTestProvider(t, fs)
	store := newMemStore()

	docs := collectDocs(t.Context(), t, p, store, true)

	// Only the device with a valid UDID is published.
	if len(docs) != 1 {
		t.Fatalf("got %d docs; want 1 (nil-UDID device must be skipped)", len(docs))
	}
	if docs[0].ID != "bbb" {
		t.Errorf("doc ID = %q; want %q", docs[0].ID, "bbb")
	}
}

func BenchmarkJamfFullSync(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("entities=%d", n), func(b *testing.B) {
			fs := &fakeServer{computers: generateComputers(n)}
			p := newBenchProvider(b, fs)

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

func BenchmarkJamfIncrementalSync(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("entities=%d", n), func(b *testing.B) {
			fs := &fakeServer{computers: generateComputers(n)}
			p := newBenchProvider(b, fs)

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
				err := p.IncrementalSync(ctx, store, pub, log)
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

func collectDocs(ctx context.Context, t *testing.T, p *jamf.Provider, store entcollect.Store, full bool) []entcollect.Document {
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

func newTestProvider(t *testing.T, fs *fakeServer) (*jamf.Provider, *httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(fs.handler(t))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}

	cfg := jamf.DefaultConfig()
	cfg.TenantID = u.Host
	cfg.Username = "user"
	cfg.Password = "pass"
	cfg.PageSize = fs.pageSize

	p := jamf.NewWithClient(cfg, srv.Client())
	return p, srv, u.Host
}

func generateComputers(n int) []jamf.Computer {
	managed := boolPtr(true)
	cs := make([]jamf.Computer, n)
	for i := range n {
		udid := fmt.Sprintf("dev-%06d", i)
		name := fmt.Sprintf("host-%d", i)
		cs[i] = jamf.Computer{UDID: strPtr(udid), Name: strPtr(name), IsManaged: managed}
	}
	return cs
}

func newBenchProvider(b *testing.B, fs *fakeServer) *jamf.Provider {
	b.Helper()
	srv := httptest.NewTLSServer(fs.handler(b))
	b.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		b.Fatalf("parse server URL: %v", err)
	}

	cfg := jamf.DefaultConfig()
	cfg.TenantID = u.Host
	cfg.Username = "user"
	cfg.Password = "pass"
	cfg.PageSize = fs.pageSize
	return jamf.NewWithClient(cfg, srv.Client())
}

// fakeServer holds the current list of computers served by the test server and
// the page size it simulates.
type fakeServer struct {
	computers []jamf.Computer
	pageSize  int
	requests  atomic.Int64
}

func (fs *fakeServer) resetRequests()     { fs.requests.Store(0) }
func (fs *fakeServer) requestCount() int64 { return fs.requests.Load() }

func (fs *fakeServer) handler(tb testing.TB) http.Handler {
	tb.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/auth/token", func(w http.ResponseWriter, r *http.Request) {
		fs.requests.Add(1)
		tok := struct {
			Token   string    `json:"token"`
			Expires time.Time `json:"expires"`
		}{
			Token:   "test-token",
			Expires: time.Now().Add(30 * time.Minute),
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(tok)
		if err != nil {
			tb.Errorf("encode token response: %v", err)
		}
	})

	mux.HandleFunc("GET /api/preview/computers", func(w http.ResponseWriter, r *http.Request) {
		fs.requests.Add(1)
		all := fs.computers
		total := len(all)

		page := 0
		pageSize := len(all)
		if v := r.URL.Query().Get("page"); v != "" {
			page, _ = strconv.Atoi(v)
		}
		if v := r.URL.Query().Get("page-size"); v != "" {
			pageSize, _ = strconv.Atoi(v)
		}

		start := page * pageSize
		end := start + pageSize
		if start > total {
			start = total
		}
		if end > total {
			end = total
		}

		resp := struct {
			TotalCount int             `json:"totalCount"`
			Results    []jamf.Computer `json:"results"`
		}{
			TotalCount: total,
			Results:    all[start:end],
		}
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(resp)
		if err != nil {
			tb.Errorf("encode computers response: %v", err)
		}
	})

	return mux
}

// memStore is a minimal in-memory Store for testing.
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

// testLogWriter bridges slog to t.Log.
type testLogWriter struct{ t *testing.T }

func newTestLogWriter(t *testing.T) *testLogWriter { return &testLogWriter{t: t} }

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

type noopWriter struct{}

func (noopWriter) Write(p []byte) (int, error) { return len(p), nil }

func boolPtr(b bool) *bool    { return &b }
func strPtr(s string) *string { return &s }

func docFieldsBytes(docs []entcollect.Document) int {
	total := 0
	for _, d := range docs {
		b, _ := json.Marshal(d.Fields)
		total += len(b)
	}
	return total
}

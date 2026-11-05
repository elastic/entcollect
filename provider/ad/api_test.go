// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ad

import (
	"context"
	"errors"
	"net"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/jimlambrt/gldap"
)

func TestParseBaseDN(t *testing.T) {
	tests := []struct {
		name                  string
		baseDN                string
		wantContainerBaseDN   string
		wantPotentialGroupDNs []string
		wantOriginalBaseDN    string
	}{
		{
			name:                "OU only",
			baseDN:              "OU=Users,DC=example,DC=com",
			wantContainerBaseDN: "ou=Users,dc=example,dc=com",
			wantOriginalBaseDN:  "ou=Users,dc=example,dc=com",
		},
		{
			name:                "DC only",
			baseDN:              "DC=example,DC=com",
			wantContainerBaseDN: "dc=example,dc=com",
			wantOriginalBaseDN:  "dc=example,dc=com",
		},
		{
			name:                  "CN before OU extracts group",
			baseDN:                "CN=Admin Users,OU=Groups,DC=example,DC=com",
			wantContainerBaseDN:   "ou=Groups,dc=example,dc=com",
			wantPotentialGroupDNs: []string{"cn=Admin Users,ou=Groups,dc=example,dc=com"},
			wantOriginalBaseDN:    "cn=Admin Users,ou=Groups,dc=example,dc=com",
		},
		{
			name:                  "CN before DC extracts group",
			baseDN:                "CN=Domain Admins,DC=example,DC=com",
			wantContainerBaseDN:   "dc=example,dc=com",
			wantPotentialGroupDNs: []string{"cn=Domain Admins,dc=example,dc=com"},
			wantOriginalBaseDN:    "cn=Domain Admins,dc=example,dc=com",
		},
		{
			name:                "nested OU",
			baseDN:              "OU=IT,OU=Departments,DC=example,DC=com",
			wantContainerBaseDN: "ou=IT,ou=Departments,dc=example,dc=com",
			wantOriginalBaseDN:  "ou=IT,ou=Departments,dc=example,dc=com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, err := ldap.ParseDN(tt.baseDN)
			if err != nil {
				t.Fatalf("failed to parse test DN %q: %v", tt.baseDN, err)
			}

			got := parseBaseDN(base)

			if got.containerBaseDN != tt.wantContainerBaseDN {
				t.Errorf("containerBaseDN = %q, want %q", got.containerBaseDN, tt.wantContainerBaseDN)
			}
			if got.originalBaseDN != tt.wantOriginalBaseDN {
				t.Errorf("originalBaseDN = %q, want %q", got.originalBaseDN, tt.wantOriginalBaseDN)
			}
			if len(got.potentialGroupDNs) != len(tt.wantPotentialGroupDNs) {
				t.Errorf("potentialGroupDNs length = %d, want %d", len(got.potentialGroupDNs), len(tt.wantPotentialGroupDNs))
			} else {
				for i, dn := range got.potentialGroupDNs {
					if dn != tt.wantPotentialGroupDNs[i] {
						t.Errorf("potentialGroupDNs[%d] = %q, want %q", i, dn, tt.wantPotentialGroupDNs[i])
					}
				}
			}
		})
	}
}

func TestParseBaseDNNil(t *testing.T) {
	got := parseBaseDN(nil)
	if got.containerBaseDN != "" || got.originalBaseDN != "" || len(got.potentialGroupDNs) != 0 {
		t.Errorf("parseBaseDN(nil) = %+v, want empty struct", got)
	}

	emptyDN := &ldap.DN{}
	got = parseBaseDN(emptyDN)
	if got.containerBaseDN != "" || got.originalBaseDN != "" || len(got.potentialGroupDNs) != 0 {
		t.Errorf("parseBaseDN(empty) = %+v, want empty struct", got)
	}
}

func TestBuildMemberOfFilter(t *testing.T) {
	tests := []struct {
		name     string
		groupDNs []string
		want     string
	}{
		{
			name: "empty",
			want: "",
		},
		{
			name:     "single group",
			groupDNs: []string{"cn=Admin Users,ou=Groups,dc=example,dc=com"},
			want:     "(memberOf:1.2.840.113556.1.4.1941:=cn=Admin Users,ou=Groups,dc=example,dc=com)",
		},
		{
			name:     "multiple groups",
			groupDNs: []string{"cn=Admins,dc=example,dc=com", "cn=Users,dc=example,dc=com"},
			want:     "(|(memberOf:1.2.840.113556.1.4.1941:=cn=Admins,dc=example,dc=com)(memberOf:1.2.840.113556.1.4.1941:=cn=Users,dc=example,dc=com))",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildMemberOfFilter(tt.groupDNs)
			if got != tt.want {
				t.Errorf("buildMemberOfFilter() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCollateEntityKey(t *testing.T) {
	groups := entries{
		"cn=Admins,dc=example,dc=com": map[string]any{
			"cn": "Admins",
		},
	}

	resp := &ldap.SearchResult{
		Entries: []*ldap.Entry{
			{
				DN: "cn=host1,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{Name: "cn", Values: []string{"host1"}},
					{Name: "memberOf", Values: []string{"cn=Admins,dc=example,dc=com"}},
				},
			},
		},
	}

	t.Run("user", func(t *testing.T) {
		dir := collate(resp, groups, "user")
		entry, ok := dir.Entries["cn=host1,dc=example,dc=com"]
		if !ok {
			t.Fatal("expected entry for cn=host1")
		}
		if _, ok := entry["user"]; !ok {
			t.Error("expected 'user' key in collated entry")
		}
		if _, ok := entry["device"]; ok {
			t.Error("unexpected 'device' key in collated entry")
		}
	})

	t.Run("device", func(t *testing.T) {
		dir := collate(resp, groups, "device")
		entry, ok := dir.Entries["cn=host1,dc=example,dc=com"]
		if !ok {
			t.Fatal("expected entry for cn=host1")
		}
		if _, ok := entry["device"]; !ok {
			t.Error("expected 'device' key in collated entry")
		}
		if _, ok := entry["user"]; ok {
			t.Error("unexpected 'user' key in collated entry")
		}
	})

	t.Run("groups_resolved", func(t *testing.T) {
		dir := collate(resp, groups, "device")
		entry := dir.Entries["cn=host1,dc=example,dc=com"]
		grps, ok := entry["groups"]
		if !ok {
			t.Fatal("expected 'groups' key in collated entry")
		}
		grpSlice, ok := grps.([]any)
		if !ok {
			t.Fatalf("expected groups to be []any, got %T", grps)
		}
		if len(grpSlice) != 1 {
			t.Fatalf("expected 1 group, got %d", len(grpSlice))
		}
	})
}

func TestWithMandatory(t *testing.T) {
	tests := []struct {
		name    string
		attrs   []string
		include []string
		want    []string
	}{
		{
			name:    "nil attrs returns nil",
			attrs:   nil,
			include: []string{"distinguishedName", "whenChanged"},
			want:    nil,
		},
		{
			name:    "empty attrs returns nil",
			attrs:   []string{},
			include: []string{"distinguishedName", "whenChanged"},
			want:    nil,
		},
		{
			name:    "missing attrs are appended",
			attrs:   []string{"cn", "mail"},
			include: []string{"distinguishedName", "whenChanged"},
			want:    []string{"cn", "mail", "distinguishedName", "whenChanged"},
		},
		{
			name:    "already present attrs are not duplicated",
			attrs:   []string{"cn", "distinguishedName", "whenChanged"},
			include: []string{"distinguishedName", "whenChanged"},
			want:    []string{"cn", "distinguishedName", "whenChanged"},
		},
		{
			name:    "partial overlap",
			attrs:   []string{"cn", "whenChanged"},
			include: []string{"distinguishedName", "whenChanged"},
			want:    []string{"cn", "whenChanged", "distinguishedName"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := withMandatory(test.attrs, test.include...)
			if len(got) != len(test.want) {
				t.Fatalf("withMandatory() = %v, want %v", got, test.want)
			}
			for i := range got {
				if got[i] != test.want[i] {
					t.Errorf("withMandatory()[%d] = %q, want %q", i, got[i], test.want[i])
				}
			}
		})
	}
}

func TestGetDetailsInvalidEntTyp(t *testing.T) {
	base, err := ldap.ParseDN("DC=example,DC=com")
	if err != nil {
		t.Fatalf("failed to parse DN: %v", err)
	}
	_, err = GetDetails(t.Context(), "(objectClass=*)", "ldap://localhost", "", "", base, time.Time{}, nil, nil, 0, nil, nil, "bogus")
	if err == nil {
		t.Fatal("expected error for invalid entTyp")
	}
	if got := err.Error(); got != `invalid entity type: "bogus"` {
		t.Errorf("unexpected error message: %s", got)
	}
}

func TestConnectBindTimeoutClosesConnection(t *testing.T) {
	setRequestTimeout(t, 100*time.Millisecond)
	srv := startSilentServer(t)

	done := make(chan error, 1)
	go func() {
		_, release, err := connect(context.Background(), "ldap://"+srv.addr, "cn=admin", "pass", nil, nil)
		if err == nil {
			release()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("connect to a server that never answers succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bind did not time out")
	}
	select {
	case <-srv.closed:
	case <-time.After(5 * time.Second):
		t.Error("connection was not closed after the bind failed")
	}
}

// setRequestTimeout sets requestTimeout to d for the duration of the test.
func setRequestTimeout(t *testing.T, d time.Duration) {
	old := requestTimeout
	requestTimeout = d
	t.Cleanup(func() { requestTimeout = old })
}

// queries are the exported LDAP queries, called with the test base DN.
var queries = []struct {
	name string
	call func(ctx context.Context, url string) error
}{
	{
		name: "GetDetails",
		call: func(ctx context.Context, url string) error {
			_, err := GetDetails(ctx, "(objectClass=*)", url, "cn=admin", "pass", testBase, time.Time{}, nil, nil, 0, nil, nil, "user")
			return err
		},
	},
	{
		name: "GetEmptyGroups",
		call: func(ctx context.Context, url string) error {
			_, err := GetEmptyGroups(ctx, url, "cn=admin", "pass", testBase, time.Time{}, nil, 0, nil, nil)
			return err
		},
	},
}

var testBase = must(ldap.ParseDN("DC=example,DC=com"))

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestCancelled(t *testing.T) {
	for _, q := range queries {
		// With ldap://, the bind is in flight when ctx is cancelled. With
		// ldaps://, the TLS handshake is: the server never answers the
		// client hello.
		for _, scheme := range []string{"ldap", "ldaps"} {
			t.Run(q.name+"_"+scheme, func(t *testing.T) {
				srv := startSilentServer(t)
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan error, 1)
				go func() { done <- q.call(ctx, scheme+"://"+srv.addr) }()
				// Cancel once the first request has reached the server.
				select {
				case <-srv.read:
				case <-time.After(5 * time.Second):
					t.Fatal("server received no request")
				}
				cancel()
				select {
				case err := <-done:
					if !errors.Is(err, context.Canceled) {
						t.Errorf("%s error = %v; want it to wrap context.Canceled", q.name, err)
					}
				case <-time.After(5 * time.Second):
					t.Fatalf("%s did not return after cancellation", q.name)
				}
				select {
				case <-srv.closed:
				case <-time.After(5 * time.Second):
					t.Error("connection was not closed after cancellation")
				}
			})
		}
	}
}

func TestAlreadyCancelled(t *testing.T) {
	for _, q := range queries {
		t.Run(q.name, func(t *testing.T) {
			srv := startSilentServer(t)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			err := q.call(ctx, "ldap://"+srv.addr)
			if !errors.Is(err, context.Canceled) {
				t.Errorf("%s error = %v; want it to wrap context.Canceled", q.name, err)
			}

			// Connections are accepted in order, so any connection the
			// query made is accepted before our probe connection.
			var d net.Dialer
			c, err := d.DialContext(t.Context(), "tcp", srv.addr)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer func() { _ = c.Close() }()
			probe := c.LocalAddr().String()
			var made int
			for {
				select {
				case addr := <-srv.accepted:
					if addr == probe {
						if made != 0 {
							t.Errorf("%s with a cancelled context made %d connections; want 0", q.name, made)
						}
						return
					}
					made++
				case <-time.After(5 * time.Second):
					t.Fatal("server did not accept the probe connection")
				}
			}
		})
	}
}

// silentServer is a TCP server that accepts connections and reads from
// them without ever answering.
type silentServer struct {
	addr string

	read     chan struct{} // closed when the server first reads data
	accepted chan string   // receives each accepted client's address
	closed   chan struct{} // receives a value each time a client closes
}

// silentServerBuffer is the capacity of the accepted and closed channels.
// The server blocks once a channel is full, so a test may make at most
// this many connections without draining them.
const silentServerBuffer = 16

func startSilentServer(t *testing.T) *silentServer {
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := &silentServer{
		addr:     ln.Addr().String(),
		read:     make(chan struct{}),
		accepted: make(chan string, silentServerBuffer),
		closed:   make(chan struct{}, silentServerBuffer),
	}
	var once sync.Once
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			srv.accepted <- conn.RemoteAddr().String()
			go func() {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 512)
				for {
					_, err := conn.Read(buf)
					if err != nil {
						srv.closed <- struct{}{}
						return
					}
					once.Do(func() { close(srv.read) })
				}
			}()
		}
	}()
	return srv
}

func TestSearchPagesByDefault(t *testing.T) {
	var (
		mu    sync.Mutex
		sizes []uint32
	)
	// Answer the first page with one group and a cookie, and the second
	// with another group and no cookie.
	url := startGLDAP(t, func(w *gldap.ResponseWriter, r *gldap.Request) {
		done := r.NewSearchDoneResponse()
		defer func() { _ = w.Write(done) }()
		msg, err := r.GetSearchMessage()
		if err != nil {
			done.SetResultCode(gldap.ResultOperationsError)
			return
		}
		var paging *gldap.ControlPaging
		for _, c := range msg.Controls {
			if p, ok := c.(*gldap.ControlPaging); ok {
				paging = p
			}
		}
		if paging == nil {
			done.SetResultCode(gldap.ResultSizeLimitExceeded)
			return
		}
		mu.Lock()
		sizes = append(sizes, paging.PagingSize)
		mu.Unlock()

		cn := "first"
		resp := &gldap.ControlPaging{Cookie: []byte("next")}
		if string(paging.Cookie) == "next" {
			cn = "second"
			resp.Cookie = nil
		}
		dn := "CN=" + cn + ",DC=example,DC=com"
		_ = w.Write(r.NewSearchResponseEntry(dn, gldap.WithAttributes(map[string][]string{
			"distinguishedName": {dn},
		})))
		done.SetControls(resp)
		done.SetResultCode(gldap.ResultSuccess)
	})

	got, err := GetEmptyGroups(t.Context(), url, "cn=admin", "pass", testBase, time.Time{}, nil, 0, nil, nil)
	if err != nil {
		t.Fatalf("GetEmptyGroups: %v", err)
	}
	var ids []string
	for _, e := range got {
		ids = append(ids, e.ID)
	}
	slices.Sort(ids)
	want := []string{"CN=first,DC=example,DC=com", "CN=second,DC=example,DC=com"}
	if !slices.Equal(ids, want) {
		t.Errorf("GetEmptyGroups IDs = %q; want %q", ids, want)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sizes) != 2 {
		t.Errorf("server received %d pages; want 2", len(sizes))
	}
	for i, size := range sizes {
		if size != defaultPagingSize {
			t.Errorf("page %d paging size = %d; want %d", i, size, defaultPagingSize)
		}
	}
}

// TestConnectionReleased checks that a completed query leaves no client
// goroutines running.
func TestConnectionReleased(t *testing.T) {
	url := startGLDAP(t, nil)
	before := runtime.NumGoroutine()
	for range 3 {
		_, err := GetEmptyGroups(t.Context(), url, "cn=admin", "pass", testBase, time.Time{}, nil, 0, nil, nil)
		if err != nil {
			t.Fatalf("GetEmptyGroups: %v", err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		buf := make([]byte, 1<<16)
		t.Errorf("%d goroutines after three queries; want at most %d as before\n%s", n, before, buf[:runtime.Stack(buf, true)])
	}
}

// startGLDAP runs a gldap server on a free port and returns its ldap://
// URL. The server accepts any bind and handles searches with search, or
// answers them with no entries if search is nil.
func startGLDAP(t *testing.T, search gldap.HandlerFunc) string {
	mux, err := gldap.NewMux()
	if err != nil {
		t.Fatalf("gldap new mux: %v", err)
	}
	err = mux.Bind(func(w *gldap.ResponseWriter, r *gldap.Request) {
		resp := r.NewBindResponse()
		resp.SetResultCode(gldap.ResultSuccess)
		_ = w.Write(resp)
	})
	if err != nil {
		t.Fatalf("mux bind: %v", err)
	}
	if search == nil {
		search = func(w *gldap.ResponseWriter, r *gldap.Request) {
			done := r.NewSearchDoneResponse()
			done.SetResultCode(gldap.ResultSuccess)
			_ = w.Write(done)
		}
	}
	err = mux.Search(search)
	if err != nil {
		t.Fatalf("mux search: %v", err)
	}

	s, err := gldap.NewServer()
	if err != nil {
		t.Fatalf("gldap new server: %v", err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	err = s.Router(mux)
	if err != nil {
		t.Fatalf("gldap router: %v", err)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	runErr := make(chan error, 1)
	go func() { runErr <- s.Run(addr) }()
	for range 100 {
		select {
		case err := <-runErr:
			t.Fatalf("gldap run: %v", err)
		default:
		}
		if s.Ready() {
			return "ldap://" + addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("gldap server not ready")
	return ""
}

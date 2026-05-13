// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ad

import (
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
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
	_, err = GetDetails("(objectClass=*)", "ldap://localhost", "", "", base, time.Time{}, nil, nil, 0, nil, nil, "bogus")
	if err == nil {
		t.Fatal("expected error for invalid entTyp")
	}
	if got := err.Error(); got != `invalid entity type: "bogus"` {
		t.Errorf("unexpected error message: %s", got)
	}
}

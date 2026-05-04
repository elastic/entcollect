// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ad

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

var (
	ErrInvalidDistinguishedName = errors.New("invalid base distinguished name")
	ErrGroups                   = errors.New("failed to get group details")
	ErrEntities                 = errors.New("failed to get entity details")
)

// Entry is an Active Directory entry with associated group membership.
// For user entries, User holds the entity attributes. For device
// (computer) entries, Device holds the entity attributes. For
// empty-group entries, Group holds the group attributes. Groups holds
// resolved group memberships for user and device entries.
type Entry struct {
	ID          string         `json:"id"`
	User        map[string]any `json:"user,omitempty"`
	Device      map[string]any `json:"device,omitempty"`
	Group       map[string]any `json:"group,omitempty"`
	Groups      []any          `json:"groups,omitempty"`
	WhenChanged time.Time      `json:"whenChanged"`
}

// parsedBaseDN holds the result of parsing a base DN for potential group components.
type parsedBaseDN struct {
	containerBaseDN   string
	potentialGroupDNs []string
	originalBaseDN    string
}

// parseBaseDN analyzes a distinguished name and separates potential group (CN)
// components from container components (OU, DC). CN components that appear
// before container components are extracted as potential group references
// that need to be validated against LDAP.
func parseBaseDN(base *ldap.DN) parsedBaseDN {
	result := parsedBaseDN{}
	if base == nil || len(base.RDNs) == 0 {
		return result
	}

	result.originalBaseDN = base.String()

	containerStart := -1
	for i, rdn := range base.RDNs {
		if len(rdn.Attributes) == 0 {
			continue
		}
		attrType := strings.ToUpper(rdn.Attributes[0].Type)
		if attrType == "OU" || attrType == "DC" {
			containerStart = i
			break
		}
	}

	if containerStart <= 0 {
		result.containerBaseDN = result.originalBaseDN
		return result
	}

	for i := 0; i < containerStart; i++ {
		rdn := base.RDNs[i]
		if len(rdn.Attributes) == 0 {
			continue
		}
		attrType := strings.ToUpper(rdn.Attributes[0].Type)
		if attrType == "CN" {
			groupRDNs := base.RDNs[i:]
			groupDN := &ldap.DN{RDNs: groupRDNs}
			result.potentialGroupDNs = append(result.potentialGroupDNs, groupDN.String())
		}
	}

	containerRDNs := base.RDNs[containerStart:]
	containerBase := &ldap.DN{RDNs: containerRDNs}
	result.containerBaseDN = containerBase.String()

	return result
}

// validateGroupDNs queries LDAP to verify which of the potential group DNs
// are actually groups (objectClass=group) vs containers or other object types.
func validateGroupDNs(conn *ldap.Conn, potentialGroupDNs []string) []string {
	if len(potentialGroupDNs) == 0 {
		return nil
	}

	var confirmedGroups []string
	for _, dn := range potentialGroupDNs {
		srch := &ldap.SearchRequest{
			BaseDN:       dn,
			Scope:        ldap.ScopeBaseObject,
			DerefAliases: ldap.NeverDerefAliases,
			SizeLimit:    1,
			Filter:       "(objectClass=group)",
			Attributes:   []string{"objectClass"},
		}

		result, err := conn.Search(srch)
		if err != nil {
			continue
		}
		if len(result.Entries) > 0 {
			confirmedGroups = append(confirmedGroups, dn)
		}
	}

	return confirmedGroups
}

// buildMemberOfFilter creates an LDAP memberOf filter from a list of group DNs.
// Uses the LDAP_MATCHING_RULE_IN_CHAIN matching rule (OID 1.2.840.113556.1.4.1941)
// to resolve nested membership at query time.
func buildMemberOfFilter(groupDNs []string) string {
	if len(groupDNs) == 0 {
		return ""
	}

	if len(groupDNs) == 1 {
		return "(memberOf:1.2.840.113556.1.4.1941:=" + ldap.EscapeFilter(groupDNs[0]) + ")"
	}

	var parts []string
	for _, dn := range groupDNs {
		parts = append(parts, "(memberOf:1.2.840.113556.1.4.1941:="+ldap.EscapeFilter(dn)+")")
	}
	return "(|" + strings.Join(parts, "") + ")"
}

// GetDetails returns entities from Active Directory matching query at the
// given LDAP URL. Group membership details are collected and joined to the
// returned entries.
//
// entTyp controls which Entry field receives the entity attributes:
// "user" populates Entry.User, "device" populates Entry.Device.
//
// If since is non-zero, only records with whenChanged since that time are
// returned. When a group has changed since that time, members of that group
// are also re-fetched (Quirk 6: group-change re-emit).
func GetDetails(query, url, user, pass string, base *ldap.DN, since time.Time, entityAttrs, grpAttrs []string, pagingSize uint32, dialer *net.Dialer, tlsconfig *tls.Config, entTyp string) ([]Entry, error) {
	switch entTyp {
	case "user", "device":
	default:
		return nil, fmt.Errorf("invalid entity type: %q", entTyp)
	}
	if base == nil || len(base.RDNs) == 0 {
		return nil, fmt.Errorf("%w: no path", ErrInvalidDistinguishedName)
	}

	var opts []ldap.DialOpt
	if dialer != nil {
		opts = append(opts, ldap.DialWithDialer(dialer))
	}
	if tlsconfig != nil {
		opts = append(opts, ldap.DialWithTLSConfig(tlsconfig))
	}
	conn, err := ldap.DialURL(url, opts...)
	if err != nil {
		return nil, err
	}

	err = conn.Bind(user, pass)
	if err != nil {
		return nil, err
	}
	defer conn.Unbind() //nolint:errcheck

	var errs []error

	var sinceFmtd string
	if !since.IsZero() {
		const denseTimeLayout = "20060102150405.0Z"
		sinceFmtd = since.Format(denseTimeLayout)
	}

	parsed := parseBaseDN(base)
	confirmedGroups := validateGroupDNs(conn, parsed.potentialGroupDNs)

	var baseDN, memberOfFilter string
	if len(confirmedGroups) > 0 {
		baseDN = parsed.containerBaseDN
		memberOfFilter = buildMemberOfFilter(confirmedGroups)
	} else {
		baseDN = parsed.originalBaseDN
	}

	// Get groups in the directory. Get all groups independent of the
	// since parameter as they may not have changed for changed entities.
	var groups directory
	grps, err := search(conn, baseDN, "(objectClass=group)", grpAttrs, pagingSize)
	if err != nil {
		errs = []error{fmt.Errorf("%w: %w", ErrGroups, err)}
		groups.Entries = entries{}
	} else {
		groups = collate(grps, nil, "")
	}

	// Get entities matching the query.
	entityFilter := query
	if memberOfFilter != "" {
		entityFilter = "(&" + query + memberOfFilter + ")"
	}
	if sinceFmtd != "" {
		entityFilter = "(&" + entityFilter + "(whenChanged>=" + sinceFmtd + "))"
	}
	ents, err := search(conn, baseDN, entityFilter, entityAttrs, pagingSize)
	if err != nil {
		errs = append(errs, fmt.Errorf("%w: %w", ErrEntities, err))
		return nil, errors.Join(errs...)
	}
	entities := collate(ents, groups.Entries, entTyp)

	// Also collect entities that are members of groups that have changed.
	if sinceFmtd != "" {
		grps, err := search(conn, baseDN, "(&(objectClass=group)(whenChanged>="+sinceFmtd+"))", grpAttrs, pagingSize)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to collect changed groups: %w: %w", ErrGroups, err))
		} else {
			changedGroups := collate(grps, nil, "")

			var modGrps []string
			for _, e := range changedGroups.Entries {
				dn, ok := e["distinguishedName"].(string)
				if !ok {
					continue
				}
				modGrps = append(modGrps, dn)
			}
			if len(modGrps) != 0 {
				for i, u := range modGrps {
					modGrps[i] = "(memberOf:1.2.840.113556.1.4.1941:=" + ldap.EscapeFilter(u) + ")"
				}
				changedGrpFilter := "(&" + query + "(|" + strings.Join(modGrps, "") + "))"
				if memberOfFilter != "" {
					changedGrpFilter = "(&" + changedGrpFilter + memberOfFilter + ")"
				}
				ents, err := search(conn, baseDN, changedGrpFilter, entityAttrs, pagingSize)
				if err != nil {
					errs = append(errs, fmt.Errorf("failed to collect entities of changed groups: %w: %w", ErrEntities, err))
				} else {
					for dn, u := range collate(ents, changedGroups.Entries, entTyp).Entries {
						if _, ok := entities.Entries[dn]; ok {
							continue
						}
						entities.Entries[dn] = u
					}
				}
			}
		}
	}

	// Assemble into a set of documents.
	docs := make([]Entry, 0, len(entities.Entries))
	for id, u := range entities.Entries {
		attrs := u[entTyp].(map[string]any)
		var groups []any
		switch g := u["groups"].(type) {
		case nil:
		case []any:
			groups = g
		}
		e := Entry{ID: id, Groups: groups, WhenChanged: whenChanged(attrs, groups)}
		switch entTyp {
		case "user":
			e.User = attrs
		case "device":
			e.Device = attrs
		default:
			panic("unreachable")
		}
		docs = append(docs, e)
	}
	return docs, errors.Join(errs...)
}

// GetEmptyGroups returns groups that have no direct members. If since is
// non-zero, only groups with whenChanged since that time are returned.
func GetEmptyGroups(url, user, pass string, base *ldap.DN, since time.Time, grpAttrs []string, pagingSize uint32, dialer *net.Dialer, tlsconfig *tls.Config) ([]Entry, error) {
	if base == nil || len(base.RDNs) == 0 {
		return nil, fmt.Errorf("%w: no path", ErrInvalidDistinguishedName)
	}

	var opts []ldap.DialOpt
	if dialer != nil {
		opts = append(opts, ldap.DialWithDialer(dialer))
	}
	if tlsconfig != nil {
		opts = append(opts, ldap.DialWithTLSConfig(tlsconfig))
	}
	conn, err := ldap.DialURL(url, opts...)
	if err != nil {
		return nil, err
	}

	err = conn.Bind(user, pass)
	if err != nil {
		return nil, err
	}
	defer conn.Unbind() //nolint:errcheck

	parsed := parseBaseDN(base)
	baseDN := parsed.originalBaseDN
	if len(parsed.potentialGroupDNs) > 0 {
		baseDN = parsed.containerBaseDN
	}

	filter := "(&(objectClass=group)(!(member=*)))"
	if !since.IsZero() {
		const denseTimeLayout = "20060102150405.0Z"
		filter = "(&(objectClass=group)(!(member=*))(whenChanged>=" + since.Format(denseTimeLayout) + "))"
	}

	result, err := search(conn, baseDN, filter, grpAttrs, pagingSize)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrGroups, err)
	}

	groups := collate(result, nil, "")
	docs := make([]Entry, 0, len(groups.Entries))
	for _, g := range groups.Entries {
		dn, _ := g["distinguishedName"].(string)
		wc, _ := g["whenChanged"].(time.Time)
		docs = append(docs, Entry{ID: dn, Group: g, WhenChanged: wc})
	}
	return docs, nil
}

func whenChanged(entity map[string]any, groups []any) time.Time {
	l, _ := entity["whenChanged"].(time.Time)
	for _, g := range groups {
		g, ok := g.(map[string]any)
		if !ok {
			continue
		}
		gl, ok := g["whenChanged"].(time.Time)
		if !ok {
			continue
		}
		if gl.After(l) {
			l = gl
		}
	}
	return l
}

func search(conn *ldap.Conn, base, filter string, attrs []string, pagingSize uint32) (*ldap.SearchResult, error) {
	srch := &ldap.SearchRequest{
		BaseDN:       base,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    0,
		TimeLimit:    0,
		TypesOnly:    false,
		Filter:       filter,
		Attributes:   attrs,
	}
	if pagingSize != 0 {
		return conn.SearchWithPaging(srch, pagingSize)
	}
	return conn.Search(srch)
}

type entries map[string]map[string]any

type directory struct {
	Entries   entries  `json:"entries"`
	Referrals []string `json:"referrals"`
	Controls  []string `json:"controls"`
}

// collate renders an LDAP search result into a map, annotating with group
// membership if available. entTyp labels the entity attributes when group
// membership is resolved (e.g. "user" or "device"); it is ignored when
// groups is nil.
func collate(resp *ldap.SearchResult, groups entries, entTyp string) directory {
	dir := directory{
		Entries: make(entries),
	}
	for _, e := range resp.Entries {
		u := make(map[string]any)
		m := u
		if groups != nil {
			m = map[string]any{entTyp: u}
		}
		for _, attr := range e.Attributes {
			val := entype(attr)
			u[attr.Name] = val
			if groups != nil && attr.Name == "memberOf" {
				switch val := val.(type) {
				case []string:
					if len(val) != 0 {
						grps := make([]any, 0, len(val))
						for _, n := range val {
							g, ok := groups[n]
							if !ok {
								continue
							}
							grps = append(grps, g)
						}
						if len(grps) != 0 {
							m["groups"] = grps
						}
					}

				case string:
					g, ok := groups[val]
					if ok {
						m["groups"] = []any{g}
					}
				}
			}
		}
		dir.Entries[e.DN] = m
	}

	if len(resp.Referrals) != 0 {
		dir.Referrals = resp.Referrals
	}
	if len(resp.Controls) != 0 {
		dir.Controls = make([]string, 0, len(resp.Controls))
		for _, e := range resp.Controls {
			if e == nil {
				continue
			}
			dir.Controls = append(dir.Controls, e.String())
		}
	}

	return dir
}

// entype converts LDAP attributes with known types to their known type if
// possible, falling back to the string if not.
func entype(attr *ldap.EntryAttribute) any {
	if len(attr.Values) == 0 {
		return attr.Values
	}
	switch attr.Name {
	case "isCriticalSystemObject", "showInAdvancedViewOnly":
		if len(attr.Values) != 1 {
			return attr.Values
		}
		switch {
		case strings.EqualFold(attr.Values[0], "true"):
			return true
		case strings.EqualFold(attr.Values[0], "false"):
			return false
		default:
			return attr.Values[0]
		}
	case "whenCreated", "whenChanged", "dSCorePropagationData":
		var times []time.Time
		if len(attr.Values) > 1 {
			times = make([]time.Time, 0, len(attr.Values))
		}
		for _, v := range attr.Values {
			const denseTimeLayout = "20060102150405.999999999Z"
			t, err := time.Parse(denseTimeLayout, v)
			if err != nil {
				return attr.Values
			}
			if len(attr.Values) == 1 {
				return t
			}
			times = append(times, t)
		}
		return times
	case "accountExpires", "lastLogon", "lastLogonTimestamp", "pwdLastSet":
		var times []time.Time
		if len(attr.Values) > 1 {
			times = make([]time.Time, 0, len(attr.Values))
		}
		for _, v := range attr.Values {
			ts, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return attr.Values
			}
			// See https://learn.microsoft.com/en-us/windows/win32/adschema/a-accountexpires.
			if attr.Name == "accountExpires" && (ts == 0 || ts == 0x7fff_ffff_ffff_ffff) {
				return v
			}
			if len(attr.Values) == 1 {
				return fromWindowsNT(ts)
			}
			times = append(times, fromWindowsNT(ts))
		}
		return times
	case "objectGUID", "objectSid":
		if len(attr.ByteValues) == 1 {
			return attr.ByteValues[0]
		}
		return attr.ByteValues
	}
	if len(attr.Values) == 1 {
		return attr.Values[0]
	}
	return attr.Values
}

const epochDelta = 116444736000000000

var unixEpoch = time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)

func fromWindowsNT(ts int64) time.Time {
	return unixEpoch.Add(time.Duration(ts-epochDelta) * 100)
}

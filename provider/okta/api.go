// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package okta

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ISO8601 is the time format accepted by Okta queries.
const ISO8601 = "2006-01-02T15:04:05.000Z"

const (
	maxRetryAttempts = 5
	retryBaseDelay   = time.Second
	retryMaxDelay    = 30 * time.Second
)

// User is an Okta user's details.
//
// See https://developer.okta.com/docs/reference/api/users/#user-properties for details.
type User struct {
	ID                    string         `json:"id"`
	Status                string         `json:"status"`
	Created               time.Time      `json:"created"`
	Activated             time.Time      `json:"activated"`
	StatusChanged         *time.Time     `json:"statusChanged,omitempty"`
	LastLogin             *time.Time     `json:"lastLogin,omitempty"`
	LastUpdated           time.Time      `json:"lastUpdated"`
	PasswordChanged       *time.Time     `json:"passwordChanged,omitempty"`
	Type                  map[string]any `json:"type"`
	TransitioningToStatus *string        `json:"transitioningToStatus,omitempty"`
	Profile               map[string]any `json:"profile"`
	Credentials           *Credentials   `json:"credentials,omitempty"`
	Links                 HAL            `json:"_links,omitempty"`
	Embedded              map[string]any `json:"_embedded,omitempty"`
}

// Credentials is a redacted Okta user's credential details. Only the
// credential provider is retained.
//
// See https://developer.okta.com/docs/reference/api/users/#credentials-object for details.
type Credentials struct {
	Password         *struct{}    `json:"password,omitempty"`
	RecoveryQuestion *struct{}    `json:"recovery_question,omitempty"`
	Provider         AuthProvider `json:"provider"`
}

// AuthProvider is an Okta credential provider.
//
// See https://developer.okta.com/docs/reference/api/users/#provider-object for details.
type AuthProvider struct {
	Type string  `json:"type"`
	Name *string `json:"name,omitempty"`
}

// Group is an Okta group.
//
// See https://developer.okta.com/docs/reference/api/groups/ for details.
type Group struct {
	ID      string         `json:"id"`
	Profile map[string]any `json:"profile"`
}

// Factor is an Okta identity factor description.
//
// See https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserFactor/#tag/UserFactor/operation/listFactors.
type Factor struct {
	ID          string         `json:"id"`
	FactorType  string         `json:"factorType"`
	Provider    string         `json:"provider"`
	VendorName  string         `json:"vendorName"`
	Status      string         `json:"status"`
	Created     time.Time      `json:"created"`
	LastUpdated time.Time      `json:"lastUpdated"`
	Profile     map[string]any `json:"profile"`
	Links       HAL            `json:"_links,omitempty"`
	Embedded    map[string]any `json:"_embedded,omitempty"`
}

// Role is an Okta user role description.
//
// See https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleAssignmentAUser/#tag/RoleAssignmentAUser/operation/listAssignedRolesForUser.
type Role struct {
	ID             string       `json:"id"`
	RoleID         string       `json:"role,omitempty"`
	Label          string       `json:"label"`
	Type           string       `json:"type"`
	Status         string       `json:"status"`
	Created        time.Time    `json:"created"`
	LastUpdated    time.Time    `json:"lastUpdated"`
	AssignmentType string       `json:"assignmentType"`
	Links          HAL          `json:"_links"`
	Permissions    []Permission `json:"permissions,omitempty"`
}

// Permission is an Okta role permission.
//
// See https://developer.okta.com/docs/api/openapi/okta-management/management/tags/roleecustompermission.
type Permission struct {
	Label       string    `json:"label"`
	Created     time.Time `json:"created"`
	LastUpdated time.Time `json:"lastUpdated"`
	Links       HAL       `json:"_links,omitempty"`
}

// Device is an Okta device's details.
//
// See https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Device/#tag/Device/operation/listDevices for details.
type Device struct {
	Created             time.Time         `json:"created"`
	ID                  string            `json:"id"`
	LastUpdated         time.Time         `json:"lastUpdated"`
	Profile             map[string]any    `json:"profile"`
	ResourceAlternateID string            `json:"resourceAlternateID"`
	ResourceDisplayName DeviceDisplayName `json:"resourceDisplayName"`
	ResourceID          string            `json:"resourceID"`
	ResourceType        string            `json:"resourceType"`
	Status              string            `json:"status"`
	Links               HAL               `json:"_links,omitempty"`

	// Users is populated by GetDeviceUsers, not the list devices response.
	Users []User `json:"users,omitempty"`
}

// DeviceDisplayName is an Okta device's annotated display name.
type DeviceDisplayName struct {
	Sensitive bool   `json:"sensitive"`
	Value     string `json:"value"`
}

// SupervisedUser holds the subset of Okta user fields used for the
// supervises enrichment.
type SupervisedUser struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Username string `json:"username"`
}

// HAL is a JSON Hypertext Application Language object.
//
// See https://datatracker.ietf.org/doc/html/draft-kelly-json-hal-06 for details.
type HAL map[string]any

// Response controls which parts of the Okta API response are omitted.
//
// See https://developer.okta.com/docs/reference/api/users/#content-type-header-fields-2.
type Response uint8

const (
	OmitCredentials Response = 1 << iota
	OmitCredentialsLinks
	OmitTransitioningToStatus
	OmitNone Response = 0
)

var oktaResponseFields = [...]string{
	"omitCredentials",
	"omitCredentialsLinks",
	"omitTransitioningToStatus",
}

func (o Response) String() string {
	if o == OmitNone {
		return ""
	}
	var buf strings.Builder
	buf.WriteString("okta-response=")
	var n int
	for i, s := range &oktaResponseFields {
		if o&(1<<i) != 0 {
			if n != 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(s)
			n++
		}
	}
	return buf.String()
}

// Error is an Okta API error value.
type Error struct {
	Code    string  `json:"errorCode,omitempty"`
	Summary string  `json:"errorSummary,omitempty"`
	Link    string  `json:"errorLink,omitempty"`
	ID      string  `json:"errorId,omitempty"`
	Causes  []Error `json:"errorCauses,omitempty"`
}

func (e *Error) Error() string {
	summary := strings.ToLower(strings.TrimRight(e.Summary, "."))
	if len(e.Causes) == 0 {
		return summary
	}
	causes := make([]string, len(e.Causes))
	for i, c := range e.Causes {
		causes[i] = c.Error()
	}
	return fmt.Sprintf("%s: %s", summary, strings.Join(causes, ","))
}

// permissionsWrapper deserialises the /api/v1/iam/roles/{roleId}/permissions
// response, which returns {"permissions":[...]} rather than a plain JSON array.
type permissionsWrapper struct {
	Permissions []Permission `json:"permissions"`
}

// devUser unwraps the _embedded.user object in device user responses.
type devUser struct {
	User `json:"user"`
}

// entity is the type constraint for the generic get function.
type entity interface {
	User | Group | Role | Factor | Device | devUser | permissionsWrapper
}

// GetUsers returns users from the Okta list users API. If query is nil, all
// active users are returned (excluding DEPROVISIONED). To include all statuses,
// pass search=status pr.
func GetUsers(ctx context.Context, cli *http.Client, host, key string, query url.Values, omit Response, lim *RateLimiter, log *slog.Logger) ([]User, http.Header, error) {
	u := &url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     "/api/v1/users",
		RawQuery: query.Encode(),
	}
	return get[User](ctx, cli, u, "/api/v1/users", key, omit, lim, log)
}

// GetGroups returns all groups from the Okta list groups API (paginated).
func GetGroups(ctx context.Context, cli *http.Client, host, key string, query url.Values, lim *RateLimiter, log *slog.Logger) ([]Group, http.Header, error) {
	u := &url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     "/api/v1/groups",
		RawQuery: query.Encode(),
	}
	return get[Group](ctx, cli, u, "/api/v1/groups", key, OmitNone, lim, log)
}

// GetGroupMembers returns the users that are members of the specified group.
func GetGroupMembers(ctx context.Context, cli *http.Client, host, key, groupID string, query url.Values, lim *RateLimiter, log *slog.Logger) ([]User, http.Header, error) {
	if groupID == "" {
		return nil, nil, errors.New("no group specified")
	}
	const endpoint = "/api/v1/groups/{groupId}/users"
	path := strings.Replace(endpoint, "{groupId}", groupID, 1)
	u := &url.URL{Scheme: "https", Host: host, Path: path, RawQuery: query.Encode()}
	return get[User](ctx, cli, u, endpoint, key, OmitNone, lim, log)
}

// GetUserGroups returns the groups a specific user belongs to.
func GetUserGroups(ctx context.Context, cli *http.Client, host, key, userID string, lim *RateLimiter, log *slog.Logger) ([]Group, http.Header, error) {
	if userID == "" {
		return nil, nil, errors.New("no user specified")
	}
	const endpoint = "/api/v1/users/{user}/groups"
	path := strings.Replace(endpoint, "{user}", userID, 1)
	u := &url.URL{Scheme: "https", Host: host, Path: path}
	return get[Group](ctx, cli, u, endpoint, key, OmitNone, lim, log)
}

// GetUserFactors returns the enrolled factors for a user.
func GetUserFactors(ctx context.Context, cli *http.Client, host, key, userID string, lim *RateLimiter, log *slog.Logger) ([]Factor, http.Header, error) {
	if userID == "" {
		return nil, nil, errors.New("no user specified")
	}
	const endpoint = "/api/v1/users/{user}/factors"
	path := strings.Replace(endpoint, "{user}", userID, 1)
	u := &url.URL{Scheme: "https", Host: host, Path: path}
	return get[Factor](ctx, cli, u, endpoint, key, OmitNone, lim, log)
}

// GetUserRoles returns the assigned roles for a user.
func GetUserRoles(ctx context.Context, cli *http.Client, host, key, userID string, lim *RateLimiter, log *slog.Logger) ([]Role, http.Header, error) {
	if userID == "" {
		return nil, nil, errors.New("no user specified")
	}
	const endpoint = "/api/v1/users/{user}/roles"
	path := strings.Replace(endpoint, "{user}", userID, 1)
	u := &url.URL{Scheme: "https", Host: host, Path: path}
	return get[Role](ctx, cli, u, endpoint, key, OmitNone, lim, log)
}

// GetRolePermissions returns the permissions for a custom role.
// The Okta API returns a single object {"permissions":[...]} here,
// not a JSON array, so we use getSingle rather than get.
func GetRolePermissions(ctx context.Context, cli *http.Client, host, key, roleID string, lim *RateLimiter, log *slog.Logger) ([]Permission, http.Header, error) {
	if roleID == "" {
		return nil, nil, errors.New("no role ID specified")
	}
	const endpoint = "/api/v1/iam/roles/{roleId}/permissions"
	path := strings.Replace(endpoint, "{roleId}", roleID, 1)
	u := &url.URL{Scheme: "https", Host: host, Path: path}
	result, h, err := getSingle[permissionsWrapper](ctx, cli, u, endpoint, key, lim, log)
	if err != nil {
		return nil, h, err
	}
	return result.Permissions, h, nil
}

// GetDevices returns devices from the Okta list devices API.
func GetDevices(ctx context.Context, cli *http.Client, host, key string, query url.Values, lim *RateLimiter, log *slog.Logger) ([]Device, http.Header, error) {
	u := &url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     "/api/v1/devices",
		RawQuery: query.Encode(),
	}
	return get[Device](ctx, cli, u, "/api/v1/devices", key, OmitNone, lim, log)
}

// GetDeviceUsers returns the users associated with a device.
func GetDeviceUsers(ctx context.Context, cli *http.Client, host, key, deviceID string, query url.Values, omit Response, lim *RateLimiter, log *slog.Logger) ([]User, http.Header, error) {
	if deviceID == "" {
		return nil, nil, nil
	}
	const endpoint = "/api/v1/devices/{device}/users"
	path := strings.Replace(endpoint, "{device}", deviceID, 1)
	u := &url.URL{
		Scheme:   "https",
		Host:     host,
		Path:     path,
		RawQuery: query.Encode(),
	}
	raw, h, err := get[devUser](ctx, cli, u, endpoint, key, omit, lim, log)
	if err != nil {
		return nil, h, err
	}
	users := make([]User, len(raw))
	for i := range raw {
		users[i] = raw[i].User
	}
	return users, h, nil
}

// GetUserDevices returns the devices enrolled by a user.
func GetUserDevices(ctx context.Context, cli *http.Client, host, key, userID string, lim *RateLimiter, log *slog.Logger) ([]Device, http.Header, error) {
	if userID == "" {
		return nil, nil, errors.New("no user specified")
	}
	const endpoint = "/api/v1/users/{user}/devices"
	path := strings.Replace(endpoint, "{user}", userID, 1)
	u := &url.URL{Scheme: "https", Host: host, Path: path}
	return get[Device](ctx, cli, u, endpoint, key, OmitNone, lim, log)
}

// get is the generic HTTP request function for the Okta API.
// It unmarshals the JSON response body as an array of E.
func get[E entity](ctx context.Context, cli *http.Client, u *url.URL, endpoint, key string, omit Response, lim *RateLimiter, log *slog.Logger) ([]E, http.Header, error) {
	body, h, err := doRequest(ctx, cli, u, endpoint, key, omit, lim, log)
	if err != nil {
		return nil, h, err
	}
	var e []E
	if err := json.Unmarshal(body, &e); err != nil {
		return nil, nil, recoverError(body)
	}
	return e, h, nil
}

// getSingle is like get but unmarshals the response as a single JSON
// object rather than an array. Use for endpoints that return an object
// wrapping a nested array (e.g. /api/v1/iam/roles/{roleId}/permissions).
func getSingle[E entity](ctx context.Context, cli *http.Client, u *url.URL, endpoint, key string, lim *RateLimiter, log *slog.Logger) (E, http.Header, error) {
	var zero E
	body, h, err := doRequest(ctx, cli, u, endpoint, key, OmitNone, lim, log)
	if err != nil {
		return zero, h, err
	}
	var e E
	if err := json.Unmarshal(body, &e); err != nil {
		return zero, nil, recoverError(body)
	}
	return e, h, nil
}

// doRequest executes an HTTP GET with retries, rate limiting, and
// exponential backoff. It returns the raw response body on success.
func doRequest(ctx context.Context, cli *http.Client, u *url.URL, endpoint, key string, omit Response, lim *RateLimiter, log *slog.Logger) ([]byte, http.Header, error) {
	target := u.String()
	for attempt := range maxRetryAttempts {
		if attempt > 0 {
			d := retryDelay(attempt)
			log.Warn("retrying request", "retry", attempt, "max", maxRetryAttempts, "backoff", d, "url", target)
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(d):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Accept", "application/json")
		contentType := "application/json"
		if omit != OmitNone {
			contentType += "; " + omit.String()
		}
		req.Header.Set("Content-Type", contentType)

		if key != "" {
			req.Header.Set("Authorization", "SSWS "+key)
		}

		if err := lim.Wait(ctx, endpoint); err != nil {
			return nil, nil, err
		}
		resp, err := cli.Do(req)
		if err != nil {
			if isContextErr(err) {
				return nil, nil, err
			}
			log.Warn("request failed", "error", err, "url", target)
			continue
		}

		err = lim.Update(endpoint, resp.Header, log)
		if err != nil {
			resp.Body.Close()
			return nil, nil, err
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			continue
		}

		var body bytes.Buffer
		_, err = io.Copy(&body, resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, nil, err
		}
		if body.Len() == 0 {
			return nil, nil, errors.New("empty response body")
		}

		if resp.StatusCode != http.StatusOK {
			return nil, resp.Header, recoverError(body.Bytes())
		}

		return body.Bytes(), resp.Header, nil
	}
	return nil, nil, fmt.Errorf("all %d attempts failed", maxRetryAttempts)
}

func recoverError(msg []byte) error {
	var e Error
	if err := json.Unmarshal(msg, &e); err != nil {
		return err
	}
	return &e
}

// Next returns the next URL query for a pagination sequence. If no further
// page is available, Next returns io.EOF.
func Next(h http.Header) (url.Values, error) {
	for _, v := range h.Values("link") {
		f := strings.Split(v, ";")
		if len(f) == 1 {
			continue
		}
		for _, p := range f[1:] {
			_, rel, ok := strings.Cut(p, "rel")
			if !ok {
				continue
			}
			_, rel, ok = strings.Cut(rel, "=")
			if !ok {
				continue
			}
			if strings.HasPrefix(strings.TrimSpace(rel), `"next"`) {
				u, err := url.Parse(strings.TrimFunc(f[0], func(r rune) bool { return r == '<' || r == '>' || r == ' ' }))
				if err != nil {
					return nil, err
				}
				return u.Query(), nil
			}
		}
	}
	return nil, io.EOF
}

func retryDelay(attempt int) time.Duration {
	d := time.Duration(1<<uint(attempt-1)) * retryBaseDelay
	if d > retryMaxDelay {
		d = retryMaxDelay
	}
	return d
}

func isContextErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package entraid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	maxRetryAttempts = 5
	retryBaseDelay   = time.Second
	retryMaxDelay    = 30 * time.Second

	odataTypeUser   = "#microsoft.graph.user"
	odataTypeGroup  = "#microsoft.graph.group"
	odataTypeDevice = "#microsoft.graph.device"
)

// ErrDeltaExpired is returned when a stored delta link has expired
// and the API returns 400 or 410. Callers should clear the delta
// link and retry with a full query.
var ErrDeltaExpired = errors.New("delta link expired")

// Group is an EntraID directory group.
type Group struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// Member is a member entry from a group's member list.
type Member struct {
	ID      string   `json:"id"`
	Type    string   `json:"@odata.type"`
	Removed *removed `json:"@removed,omitempty"`
}

// MFADetails holds MFA registration details for a user.
type MFADetails struct {
	IsMFACapable                                  bool     `json:"isMfaCapable"`
	IsMFARegistered                               bool     `json:"isMfaRegistered"`
	IsPasswordlessCapable                         bool     `json:"isPasswordlessCapable"`
	IsSsprCapable                                 bool     `json:"isSsprCapable"`
	IsSsprEnabled                                 bool     `json:"isSsprEnabled"`
	IsSsprRegistered                              bool     `json:"isSsprRegistered"`
	IsSystemPreferredAuthenticationMethodEnabled  bool     `json:"isSystemPreferredAuthenticationMethodEnabled"`
	MethodsRegistered                             []string `json:"methodsRegistered"`
	SystemPreferredAuthenticationMethods          []string `json:"systemPreferredAuthenticationMethods"`
	UserPreferredMethodForSecondaryAuthentication string   `json:"userPreferredMethodForSecondaryAuthentication"`
	UserType                                      string   `json:"userType"`
}

// SignInActivityDetails holds sign-in activity timestamps for a user.
// This data is not persisted; it is repopulated each sync cycle when
// the "sign_in_activity" enrich_with option is set.
type SignInActivityDetails struct {
	LastSignInDateTime                string `json:"lastSignInDateTime,omitempty"`
	LastSignInRequestID               string `json:"lastSignInRequestId,omitempty"`
	LastNonInteractiveSignInDateTime  string `json:"lastNonInteractiveSignInDateTime,omitempty"`
	LastNonInteractiveSignInRequestID string `json:"lastNonInteractiveSignInRequestId,omitempty"`
	LastSuccessfulSignInDateTime      string `json:"lastSuccessfulSignInDateTime,omitempty"`
	LastSuccessfulSignInRequestID     string `json:"lastSuccessfulSignInRequestId,omitempty"`
}

// removed matches the @removed annotation in delta responses.
type removed struct {
	Reason string `json:"reason"`
}

// userEntry is a raw user from the delta API. The Fields map holds
// the $select-controlled properties. The id and @removed fields are
// extracted into typed accessors.
type userEntry struct {
	Fields  map[string]any
	id      string
	removed bool
}

func (u *userEntry) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if id, ok := raw["id"].(string); ok {
		u.id = id
		delete(raw, "id")
	}
	if _, ok := raw["@removed"]; ok {
		u.removed = true
		delete(raw, "@removed")
	}
	u.Fields = raw
	return nil
}

// deviceEntry is a raw device from the delta API.
type deviceEntry struct {
	Fields  map[string]any
	id      string
	removed bool
}

func (d *deviceEntry) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if id, ok := raw["id"].(string); ok {
		d.id = id
		delete(raw, "id")
	}
	if _, ok := raw["@removed"]; ok {
		d.removed = true
		delete(raw, "@removed")
	}
	d.Fields = raw
	return nil
}

// deltaResponse is the generic shape of a Graph API delta or paged response.
type deltaResponse[T any] struct {
	NextLink  string `json:"@odata.nextLink"`
	DeltaLink string `json:"@odata.deltaLink"`
	Value     []T    `json:"value"`
}

// graphClient wraps the HTTP plumbing for Microsoft Graph API calls.
type graphClient struct {
	baseURL    string
	token      func(context.Context) (string, error)
	resetToken func()
	client     *http.Client
	log        *slog.Logger
}

// getUsers fetches users via the delta endpoint. If deltaURL is
// non-empty, it is used as the starting URL (incremental). Returns
// all users across all pages and the new delta link.
func (g *graphClient) getUsers(ctx context.Context, deltaURL string, selectFields []string) ([]userEntry, string, error) {
	startURL := deltaURL
	if startURL == "" {
		startURL = g.baseURL + "/users/delta"
		if len(selectFields) > 0 {
			startURL += "?$select=" + strings.Join(selectFields, ",")
		}
	}
	return fetchDelta[userEntry](ctx, g, startURL, "users")
}

// getDevices fetches devices via the delta endpoint.
func (g *graphClient) getDevices(ctx context.Context, deltaURL string, selectFields []string) ([]deviceEntry, string, error) {
	startURL := deltaURL
	if startURL == "" {
		startURL = g.baseURL + "/devices/delta"
		if len(selectFields) > 0 {
			startURL += "?$select=" + strings.Join(selectFields, ",")
		}
	}
	return fetchDelta[deviceEntry](ctx, g, startURL, "devices")
}

// getGroups fetches all groups (non-delta, paginated).
func (g *graphClient) getGroups(ctx context.Context, selectFields []string) ([]Group, error) {
	startURL := g.baseURL + "/groups"
	if len(selectFields) > 0 {
		startURL += "?$select=" + strings.Join(selectFields, ",")
	}
	var all []Group
	fetchURL := startURL
	for {
		var resp deltaResponse[Group]
		if err := g.doJSON(ctx, fetchURL, &resp); err != nil {
			return nil, fmt.Errorf("fetch groups: %w", err)
		}
		all = append(all, resp.Value...)
		if resp.NextLink == "" {
			return all, nil
		}
		if resp.NextLink == fetchURL {
			return all, fmt.Errorf("groups: next link loop detected")
		}
		fetchURL = resp.NextLink
	}
}

// getGroupMembers fetches all members of a group (paginated).
func (g *graphClient) getGroupMembers(ctx context.Context, groupID string) ([]Member, error) {
	startURL := g.baseURL + "/groups/" + groupID + "/members"
	var all []Member
	fetchURL := startURL
	for {
		var resp deltaResponse[Member]
		if err := g.doJSON(ctx, fetchURL, &resp); err != nil {
			return nil, fmt.Errorf("fetch members for group %s: %w", groupID, err)
		}
		all = append(all, resp.Value...)
		if resp.NextLink == "" {
			return all, nil
		}
		if resp.NextLink == fetchURL {
			return all, fmt.Errorf("group %s members: next link loop detected", groupID)
		}
		fetchURL = resp.NextLink
	}
}

// getDeviceRegistered fetches registered owners or users for a device.
func (g *graphClient) getDeviceRegistered(ctx context.Context, deviceID, relation string) ([]map[string]any, error) {
	startURL := g.baseURL + "/devices/" + deviceID + "/" + relation
	var all []map[string]any
	fetchURL := startURL
	for {
		var resp deltaResponse[map[string]any]
		if err := g.doJSON(ctx, fetchURL, &resp); err != nil {
			return nil, fmt.Errorf("fetch %s for device %s: %w", relation, deviceID, err)
		}
		all = append(all, resp.Value...)
		if resp.NextLink == "" {
			return all, nil
		}
		if resp.NextLink == fetchURL {
			return all, fmt.Errorf("device %s %s: next link loop detected", deviceID, relation)
		}
		fetchURL = resp.NextLink
	}
}

// getMFADetails fetches MFA registration details for all users.
// Returns a map keyed by user ID.
func (g *graphClient) getMFADetails(ctx context.Context) (map[string]*MFADetails, error) {
	type mfaEntry struct {
		ID string `json:"id"`
		MFADetails
	}
	startURL := g.baseURL + "/reports/authenticationMethods/userRegistrationDetails"
	result := make(map[string]*MFADetails)
	fetchURL := startURL
	for {
		var resp deltaResponse[mfaEntry]
		if err := g.doJSON(ctx, fetchURL, &resp); err != nil {
			return nil, fmt.Errorf("fetch MFA details: %w", err)
		}
		for _, e := range resp.Value {
			d := e.MFADetails
			result[e.ID] = &d
		}
		if resp.NextLink == "" {
			return result, nil
		}
		if resp.NextLink == fetchURL {
			return result, fmt.Errorf("MFA details: next link loop detected")
		}
		fetchURL = resp.NextLink
	}
}

// getSignInActivity fetches sign-in activity for all users via
// /users?$select=id,signInActivity. Returns a map keyed by user ID.
// The signInActivity property cannot be included in delta $select —
// Microsoft stores it outside the main directory data store.
func (g *graphClient) getSignInActivity(ctx context.Context) (map[string]*SignInActivityDetails, error) {
	type signInEntry struct {
		ID             string                `json:"id"`
		SignInActivity *SignInActivityDetails `json:"signInActivity"`
	}
	startURL := g.baseURL + "/users?$select=id,signInActivity"
	result := make(map[string]*SignInActivityDetails)
	fetchURL := startURL
	for {
		var resp deltaResponse[signInEntry]
		if err := g.doJSON(ctx, fetchURL, &resp); err != nil {
			return nil, fmt.Errorf("fetch sign-in activity: %w", err)
		}
		for _, e := range resp.Value {
			if e.SignInActivity != nil {
				result[e.ID] = e.SignInActivity
			}
		}
		if resp.NextLink == "" {
			return result, nil
		}
		if resp.NextLink == fetchURL {
			return result, fmt.Errorf("sign-in activity: next link loop detected")
		}
		fetchURL = resp.NextLink
	}
}

// fetchDelta is the generic delta pagination loop. It follows
// @odata.nextLink pages until @odata.deltaLink appears, collecting
// all values. Returns ErrDeltaExpired if the API rejects the delta
// link with 400 or 410.
func fetchDelta[T any](ctx context.Context, g *graphClient, startURL, entity string) ([]T, string, error) {
	var all []T
	fetchURL := startURL
	for {
		var resp deltaResponse[T]
		if err := g.doJSON(ctx, fetchURL, &resp); err != nil {
			if errors.Is(err, ErrDeltaExpired) {
				return nil, "", ErrDeltaExpired
			}
			return nil, "", fmt.Errorf("fetch %s delta: %w", entity, err)
		}
		all = append(all, resp.Value...)
		if resp.DeltaLink != "" {
			return all, resp.DeltaLink, nil
		}
		if resp.NextLink == "" {
			return nil, "", fmt.Errorf("%s: response has neither delta link nor next link", entity)
		}
		if resp.NextLink == fetchURL {
			return nil, "", fmt.Errorf("%s: next link loop detected", entity)
		}
		fetchURL = resp.NextLink
	}
}

// doJSON executes a GET request with auth, retry, and JSON decoding.
func (g *graphClient) doJSON(ctx context.Context, reqURL string, dst any) error {
	body, err := g.doRequest(ctx, reqURL)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, dst)
}

// doRequest performs an authenticated GET with exponential backoff
// and 429/Retry-After handling. Returns the raw response body.
func (g *graphClient) doRequest(ctx context.Context, reqURL string) ([]byte, error) {
	for attempt := range maxRetryAttempts {
		if attempt > 0 {
			d := retryDelay(attempt)
			g.log.Warn("retrying request", "retry", attempt, "max", maxRetryAttempts, "backoff", d, "url", reqURL)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(d):
			}
		}

		token, err := g.token(ctx)
		if err != nil {
			return nil, fmt.Errorf("get bearer token: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")

		resp, err := g.client.Do(req)
		if err != nil {
			if isContextErr(err) {
				return nil, err
			}
			g.log.Warn("request failed", "error", err, "url", reqURL)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read response body: %w", err)
		}

		switch {
		case resp.StatusCode == http.StatusOK:
			return body, nil

		case resp.StatusCode == http.StatusTooManyRequests:
			wait := retryDelay(attempt + 1)
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs, err := strconv.Atoi(ra); err == nil {
					wait = time.Duration(secs) * time.Second
				}
			}
			g.log.Warn("rate limited", "retry_after", wait, "url", reqURL)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			continue

		case resp.StatusCode == http.StatusUnauthorized:
			g.log.Warn("unauthorized, resetting token", "url", reqURL)
			g.resetToken()
			continue

		case resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusGone:
			return nil, ErrDeltaExpired

		case resp.StatusCode >= 500:
			g.log.Warn("server error", "status", resp.StatusCode, "url", reqURL)
			continue

		default:
			return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
		}
	}
	return nil, fmt.Errorf("all %d attempts failed for %s", maxRetryAttempts, reqURL)
}

func retryDelay(attempt int) time.Duration {
	return min(time.Duration(1<<uint(attempt-1))*retryBaseDelay, retryMaxDelay)
}

func isContextErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

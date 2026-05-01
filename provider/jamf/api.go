// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package jamf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	maxRetryAttempts = 5
	retryBaseDelay   = time.Second
	retryMaxDelay    = 30 * time.Second
)

// Token is a Jamf API bearer token.
type Token struct {
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}

// valid reports whether the token will remain valid for at least grace longer.
func (t Token) valid(grace time.Duration) bool {
	return t.Token != "" && !t.Expires.IsZero() && time.Until(t.Expires) > grace
}

// GetToken obtains a bearer token for the Jamf tenant using basic auth.
func GetToken(ctx context.Context, client *http.Client, tenant, username, password string) (Token, error) {
	u := &url.URL{Scheme: "https", Host: tenant, Path: "/api/v1/auth/token"}

	var tok Token
	err := doWithRetry(ctx, client,
		func(ctx context.Context) (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Accept", "application/json")
			req.SetBasicAuth(username, password)
			return req, nil
		},
		func(body []byte) error {
			var probe struct {
				Errors any `json:"errors"`
			}
			if err := json.Unmarshal(body, &probe); err != nil {
				return err
			}
			if probe.Errors != nil {
				return parseAPIError(body)
			}
			return json.Unmarshal(body, &tok)
		},
	)
	return tok, err
}

// Computers is the response from the Jamf computers list endpoint.
type Computers struct {
	TotalCount int        `json:"totalCount"`
	Results    []Computer `json:"results"`
	Errors     any        `json:"errors,omitempty"`
}

// Computer holds the details of a Jamf-managed device.
//
// See https://developer.jamf.com/jamf-pro/reference/get_preview-computers for details.
type Computer struct {
	Location                                Location  `json:"location,omitempty"`
	Site                                    *string   `json:"site"`
	Name                                    *string   `json:"name"`
	UDID                                    *string   `json:"udid"`
	SerialNumber                            *string   `json:"serialNumber"`
	OperatingSystemVersion                  *string   `json:"operatingSystemVersion"`
	OperatingSystemBuild                    *string   `json:"operatingSystemBuild"`
	OperatingSystemSupplementalBuildVersion *string   `json:"operatingSystemSupplementalBuildVersion"`
	OperatingSystemRapidSecurityResponse    *string   `json:"operatingSystemRapidSecurityResponse"`
	MACAddress                              *string   `json:"macAddress"`
	AssetTag                                *string   `json:"assetTag"`
	ModelIdentifier                         *string   `json:"modelIdentifier"`
	MDMAccessRights                         *int      `json:"mdmAccessRights"`
	LastContactDate                         time.Time `json:"lastContactDate"`
	LastReportDate                          time.Time `json:"lastReportDate"`
	LastEnrolledDate                        time.Time `json:"lastEnrolledDate"`
	IPAddress                               *string   `json:"ipAddress"`
	ManagementID                            *string   `json:"managementId"`
	IsManaged                               *bool     `json:"isManaged"`
}

// Location is the location details for a Jamf device.
type Location struct {
	Username     *string `json:"username,omitempty"`
	RealName     *string `json:"realName,omitempty"`
	EmailAddress *string `json:"emailAddress,omitempty"`
	Position     *string `json:"position,omitempty"`
	PhoneNumber  *string `json:"phoneNumber,omitempty"`
	Department   *string `json:"department,omitempty"`
	Building     *string `json:"building,omitempty"`
	Room         *string `json:"room,omitempty"`
}

// GetComputers returns one page of computers from the Jamf Pro preview API.
// page is zero-indexed. If pageSize is zero, the server's default page size
// is used and the page parameter is omitted.
func GetComputers(ctx context.Context, client *http.Client, tenant string, tok Token, page, pageSize int) (Computers, error) {
	q := url.Values{"page": {strconv.Itoa(page)}}
	if pageSize > 0 {
		q.Set("page-size", strconv.Itoa(pageSize))
	}
	u := &url.URL{Scheme: "https", Host: tenant, Path: "/api/preview/computers", RawQuery: q.Encode()}

	var computers Computers
	err := doWithRetry(ctx, client,
		func(ctx context.Context) (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Authorization", "Bearer "+tok.Token)
			return req, nil
		},
		func(body []byte) error {
			if err := json.Unmarshal(body, &computers); err != nil {
				return err
			}
			if computers.Errors != nil {
				return parseAPIError(body)
			}
			return nil
		},
	)
	return computers, err
}

// doWithRetry executes an HTTP request, retrying on network errors and 5xx
// responses with exponential backoff. buildReq is called fresh on each
// attempt. onBody is called with the response body when the server returns
// HTTP 200; any error it returns is not retried.
func doWithRetry(ctx context.Context, client *http.Client, buildReq func(context.Context) (*http.Request, error), onBody func([]byte) error) error {
	var lastErr error
	for attempt := range maxRetryAttempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(retryDelay(attempt)):
			}
		}

		req, err := buildReq(ctx)
		if err != nil {
			return err
		}

		resp, err := client.Do(req)
		if err != nil {
			if isContextErr(err) {
				return err
			}
			lastErr = err
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("reading response body: %w", err)
			continue
		}

		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("server error: HTTP %d", resp.StatusCode)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, http.StatusText(resp.StatusCode))
		}

		return onBody(body)
	}
	return fmt.Errorf("all %d attempts failed: %w", maxRetryAttempts, lastErr)
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

// APIError is an error returned by the Jamf API.
type APIError struct {
	Status int `json:"httpStatus"`
	Errors []struct {
		Code        string `json:"code"`
		Description string `json:"description"`
	} `json:"errors"`
}

func (e *APIError) Error() string {
	if len(e.Errors) == 0 {
		return fmt.Sprintf("jamf api error: http %d", e.Status)
	}
	msgs := make([]string, len(e.Errors))
	for i, d := range e.Errors {
		msgs[i] = d.Code + ": " + d.Description
	}
	return fmt.Sprintf("jamf api error: http %d: %s", e.Status, strings.Join(msgs, "; "))
}

func parseAPIError(body []byte) error {
	var e APIError
	if err := json.Unmarshal(body, &e); err != nil {
		return fmt.Errorf("could not parse API error: %w", err)
	}
	if e.Status == 0 {
		return nil
	}
	return &e
}

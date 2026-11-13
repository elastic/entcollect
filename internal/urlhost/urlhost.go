// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package urlhost checks configured hosts that providers use to build
// API URLs.
package urlhost

import (
	"net/url"
	"strconv"
	"strings"
)

// Valid reports whether s parses as exactly the host, with an optional
// port, of an https URL, so that it can be used as the host of API URLs.
// Anything else in s, such as a scheme, user information or a path, makes
// the parsed host differ from s. An IPv6 address must be in brackets, and
// a port must be a number from 1 to 65535. It does not check the syntax
// of the host name itself.
func Valid(s string) bool {
	u, err := url.Parse("https://" + s)
	if err != nil || u.Host != s || u.Hostname() == "" {
		return false
	}
	// Depending on the main module's Go version, url.Parse may accept an
	// unbracketed IPv6 address, taking its last group as the port.
	if !strings.HasPrefix(s, "[") && strings.Contains(u.Hostname(), ":") {
		return false
	}
	if strings.HasSuffix(s, ":") {
		return false
	}
	port := u.Port()
	if port == "" {
		return true
	}
	n, err := strconv.Atoi(port)
	return err == nil && 1 <= n && n <= 65535
}

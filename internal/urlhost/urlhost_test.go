// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package urlhost

import "testing"

func TestValid(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{host: "example.com", want: true},
		{host: "127.0.0.1", want: true},
		{host: "example.com:8443", want: true},
		{host: "example.com:1", want: true},
		{host: "example.com:65535", want: true},
		{host: "[2001:db8::1]", want: true},
		{host: "[::1]:8443", want: true},

		{host: "", want: false},
		{host: "https://example.com", want: false},
		{host: "example.com/", want: false},
		{host: "example.com/api", want: false},
		{host: "user@example.com", want: false},
		{host: "example.com?a=b", want: false},
		{host: "example.com#frag", want: false},
		{host: ":8443", want: false},
		{host: "example.com:", want: false},
		{host: "example.com:0", want: false},
		{host: "example.com:65536", want: false},
		{host: "example.com:http", want: false},
		{host: "2001:db8::1", want: false},
		{host: "example com", want: false},
	}
	for _, test := range tests {
		got := Valid(test.host)
		if got != test.want {
			t.Errorf("Valid(%q) = %t; want %t", test.host, got, test.want)
		}
	}
}

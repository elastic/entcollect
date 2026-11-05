// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package okta

import "testing"

// SetFastRetry shortens the request retry delays for the duration of the
// test, for tests in package okta_test.
func SetFastRetry(t *testing.T) { setFastRetry(t) }

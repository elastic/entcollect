// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package entcollect provides shared types and interfaces for syncing
// identity data from external providers (Jamf, Okta, Active Directory,
// EntraID) into Elasticsearch. It is runtime-agnostic: both Elastic
// Beats and OpenTelemetry Collector adapters use it through thin
// adapter layers that implement [Store] and supply a [Publisher].
package entcollect

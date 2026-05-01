// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package jamf provides a Jamf device provider for the entcollect library.
//
// The provider syncs computer inventory from the Jamf Pro REST API. Both
// [Provider.FullSync] and [Provider.IncrementalSync] perform a complete
// inventory fetch on each call: Jamf has no time-filtered endpoint that would
// support a true incremental mode, so every sync emits all current devices.
//
// Deletion detection uses two mechanisms:
//   - Devices returned by the API with isManaged=false (or nil) are emitted
//     with [entcollect.ActionDeleted].
//   - Devices present in a previous sync but absent from the current API
//     response are detected via an [idset.Set] and emitted with
//     [entcollect.ActionDeleted]. This is an addition relative to the legacy
//     beats entity-analytics-jamf provider, which did not detect inventory
//     absences as deletions.
package jamf

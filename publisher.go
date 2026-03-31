// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package entcollect

import (
	"context"
	"time"
)

// Publisher delivers a single [Document] to the output pipeline.
// The adapter supplies a closure that converts the Document to the
// runtime's event format (beat.Event for Beats, plog.LogRecord for
// OTel) and publishes it. Returning a non-nil error signals that the
// provider should stop emitting documents.
type Publisher func(ctx context.Context, doc Document) error

// EntityKind identifies the category of an identity entity.
type EntityKind int

const (
	KindUser EntityKind = iota + 1
	KindDevice
	KindGroup
)

func (k EntityKind) String() string {
	switch k {
	case KindUser:
		return "user"
	case KindDevice:
		return "device"
	case KindGroup:
		return "group"
	default:
		return "unknown"
	}
}

// Action describes the lifecycle event for a [Document].
type Action int

const (
	ActionDiscovered Action = iota + 1
	ActionModified
	ActionDeleted
)

func (a Action) String() string {
	switch a {
	case ActionDiscovered:
		return "discovered"
	case ActionModified:
		return "modified"
	case ActionDeleted:
		return "deleted"
	default:
		return "unknown"
	}
}

// Document is a single entity event emitted by a provider during
// sync. Each document represents one identity entity (user, device,
// or group) and carries the lifecycle action that triggered it.
//
// The ID field is the stable identifier assigned by the identity
// provider (e.g. Okta user ID, EntraID object UUID, LDAP DN).
// Adapters use it to construct deterministic Elasticsearch _id
// values, making writes idempotent on replay.
//
// Fields contains nested, ECS-compatible data. Not all fields are
// populated by all providers; absent fields are simply omitted
// from the map.
type Document struct {
	ID        string
	Kind      EntityKind
	Action    Action
	Timestamp time.Time
	Fields    map[string]any
}

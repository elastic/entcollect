# entcollect

Shared Go library for syncing identity data from external providers
(Okta, EntraID, Active Directory, Jamf) into Elasticsearch.

Used by both Elastic Beats and OpenTelemetry Collector through thin
adapter layers. The library defines provider, store, and document
abstractions with no coupling to either runtime. Adapters handle
scheduling, configuration, and event delivery.

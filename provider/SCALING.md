# Scaling

Scaling characteristics of the entity analytics providers, focused on
EntraID's group-graph topology since that is the most complex sync path.
The final section compares API cost across all four providers.

Benchmark results. Reproduce with:

```
go test -run ^$ -bench 'BenchmarkEntraid|BenchmarkMembershipGraph' -benchtime 1s ./provider/entraid/
go test -run 'TestEntraidRateLimitProfile|TestEntraidEndToEndSanityCheck' -v -short=false ./provider/entraid/
```

## EntraID

### Ceiling methodology

Sync is problematic when total sync duration exceeds `update_interval`
(default 15 minutes / 900s). If a sync cannot complete before the next
scheduled sync fires, the system cannot converge.

**Worst-case path:** Incremental sync with at least one changed
user/device. Any change triggers full group refetch + graph rebuild,
but incremental avoids re-fetching all users/devices.

**Model inputs:** Total sync time ≈ API calls × assumed_latency + graph
CPU. The table below uses mock-measured graph CPU and states assumed
per-call latency so readers can rescale for their environment.

**Fixture assumptions:** Benchmarks use user-only fixtures (no devices).
Device graph expansion uses the same `expandTransitive` function
(identical cost). `enrichDeviceOwnership` adds 2 API calls per device
— additional device-specific overhead not included in graph scaling
numbers.

### Group-graph scaling table

| Groups | Users | Nesting | Sync path | API calls | Graph build (ms) | Per-user expand (µs) | All-users expand (ms) | Mock sync (ms) | CI/manual |
|--------|-------|---------|-----------|-----------|------------------|----------------------|-----------------------|----------------|-----------|
| 10 | 1000 | flat | incremental Δ=1 | 13 | 0.07 | 5.9 | 64 | 2 | CI |
| 100 | 1000 | flat | incremental Δ=1 | 103 | 1.1 | 5.9 | 64 | 7 | CI |
| 1000 | 1000 | flat | incremental Δ=1 | 1003 | 9.2 | 68 | 890 | 54 | CI |
| 1000 | 1000 | flat | full sync | 1003 | 9.2 | 68 | 890 | 51 | CI |
| 10000 | 1000 | flat | incremental Δ=1 | 10003 | 97 | 748 | 7624 | 448 | CI |
| 10000 | 1000 | flat | full sync | 10004 | 97 | 748 | 7624 | 534 | CI |
| 10 | 100 | flat | full sync (throttled) | 13 | — | — | — | 3 | manual |
| 100 | 100 | flat | full sync (throttled) | 105 | — | — | — | 4011 | manual |

### Delta cardinality (fixed G=1000, varying Δ)

Confirms group refetch cost is constant regardless of delta size.

| Groups | Delta users | API calls | Mock sync (ms) |
|--------|-------------|-----------|----------------|
| 1000 | 1 | 1003 | 51 |
| 1000 | 100 | 1003 | 53 |
| 1000 | 1000 | 1003 | 59 |

### No-change incremental sync

When no entities change, group fetch is skipped entirely.

| API calls | Mock sync (µs) |
|-----------|----------------|
| 2 | 115 |

### Ceiling estimate

With mock latency (local httptest, ~0.05ms/call), 10k groups completes
in ~450ms — well under the 900s ceiling. Projecting with realistic API
latency:

| Groups | API calls | Graph CPU (ms) | At 10ms/call (s) | At 50ms/call (s) | At 100ms/call (s) |
|--------|-----------|----------------|-------------------|-------------------|---------------------|
| 100 | 103 | 1.1 | 1.0 | 5.2 | 10.3 |
| 1000 | 1003 | 9.2 | 10 | 50 | 100 |
| 5000 | 5003 | ~49 | 50 | 250 | 500 |
| 10000 | 10003 | ~97 | 100 | 500 | **1000** |

**Ceiling at default `update_interval` (900s):**

- At 10ms/call: ~90,000 groups (API calls dominate)
- At 50ms/call: ~18,000 groups
- At 100ms/call: **~9,000 groups** (10k groups exceeds 900s)

Graph CPU is negligible compared to API latency at all realistic scales.
The ceiling is determined by API call count × per-call latency.

### Memoization finding

`BenchmarkMembershipGraph_AllUsers` with 1000 users × 10000 groups (flat)
runs in ~7.6s without memoization. Each `userTransitiveGroups` call
recomputes BFS independently. At 10k groups, per-user expand takes 748µs
— not a bottleneck relative to the API call cost (~50ms+ per call in
production). Memoization would help if graph CPU became dominant, but at
realistic API latencies, group fetch API calls are 100× more expensive
than graph operations. Documented for preparation for [elastic/beats#51210](https://github.com/elastic/beats/pull/51210);
no optimisation needed.

### File-backed scratch storage

The membership graph is stored in a temporary bbolt file rather than
in-memory maps. This bounds Go heap usage for large directories — the
heap holds only the BFS queue and seen set (proportional to nesting
depth), not the full adjacency data.

Dense topology benchmark (5k groups × 500 members = 2.5M edges, flat):

| Backend | Heap delta | RSS | Scratch file | Build + 100 reads |
|---------|-----------|-----|-------------|-------------------|
| bbolt (scratchBackend) | ~133 MB | ~582 MB | ~277 MB | ~11 s |
| in-memory (mapBackend) | ~114 MB | ~291 MB | — | ~0.35 s |

Key observations:

- **Heap delta** is comparable because bbolt allocations during bulk
  writes are temporary. After the write phase completes, only the
  mmap'd file and BFS working set remain — Go's garbage collector
  can reclaim write-phase allocations.
- **RSS** is higher with bbolt because the mmap'd file counts towards
  RSS. However, mmap'd pages are OS-reclaimable under memory pressure
  — unlike Go heap objects, they don't contribute to OOM kills in
  cgroup-limited containers.
- **Wall time** for the build phase is dominated by bbolt I/O. In
  production this is negligible relative to the API call latency
  (5000 group-member fetches × 50–100ms/call = 250–500s).
- **Scratch file size** of ~277 MB for 2.5M edges is within typical
  ephemeral disk limits for agentless containers.

Reproduce with:

```
go test -run ^$ -bench BenchmarkDenseTopology -benchtime 1x ./provider/entraid/
```

Configuration: `scratch_dir` in the provider config overrides the
default `os.TempDir()`. Files use the prefix `entcollect-scratch-*`
for identification and crash-cleanup.

### Rate-limit profile

Synthetic throttle policy: 429 + Retry-After: 1s every 50 requests.

| Groups | Total requests | Throttle hits | Wall-clock (s) | Throttle wait (s) |
|--------|---------------|---------------|----------------|-------------------|
| 10 | 13 | 0 | 0.003 | 0 |
| 100 | 105 | 2 | 4.0 | 2 |

At 1000 groups (~1003 requests), expect ~20 throttle hits × 1s = ~20s
additional wait. This is additive to the baseline API call time.

### End-to-end sanity check

FullSync with 1000 users × 1000 groups (flat, no throttle):

| Metric | Value |
|--------|-------|
| Documents published | 1000 |
| API calls | 1004 |
| Wall-clock time | 72ms |
| Per-API-call avg | 72µs |

The decomposed model (API calls × mock latency + graph CPU) closely
tracks the measured end-to-end time, confirming the model is sound for
scaling projections.

## Document size (Elasticsearch load)

Average serialised document size (`json.Marshal` of the `Fields` map)
from benchmark fixtures. This approximates the per-document cost in
Elasticsearch before compression, indexing overhead, and replicas.

Fixture data is minimal — real documents will be larger depending on
how many user/device attributes the identity provider returns. The
numbers below establish the structural baseline and show how group
membership affects document size.

### EntraID

| Users | Groups | Nesting | Avg doc (B) | Total payload (KB) |
|-------|--------|---------|-------------|-------------------|
| 100 | 10 | flat | 93 | 9 |
| 1000 | 10 | flat | 95 | 93 |
| 1000 | 100 | flat | 97 | 95 |
| 1000 | 1000 | flat | 99 | 97 |
| 1000 | 10000 | flat | 99 | 97 |

Group count has almost no effect on per-document size in flat
topologies because users are distributed round-robin — each user
belongs to roughly one group regardless of total group count. Nested
or diamond topologies with transitive expansion would increase this.

### Other providers

| Provider | Entities | Avg doc (B) |
|----------|----------|-------------|
| AD | 10–1000 | 264 |
| Okta | 10 users / 1 group | 277 |
| Okta | 1000 users / 50 groups | 284 |
| Jamf | 100–1000 | 524 |

Jamf documents are largest because `Computer` structs carry hardware
and OS inventory fields. AD and Okta are mid-range. EntraID is
smallest because the fixture users have minimal attributes.

### Projection

At 10,000 users with 500 B average doc size (realistic with full
attributes), total payload per full sync ≈ 5 MB uncompressed. With
a 15-minute sync interval, that is ~480 MB/day before replicas —
modest for Elasticsearch.

## Cross-provider API cost comparison

| Provider | Legacy (beats) | Minimal-state (entcollect) | Impact |
|----------|---------------|---------------------------|--------|
| EntraID groups | `/groups/delta` + `members@delta` (incremental) | `GET /groups` + per-group `/members` (full refetch every active sync) | Minimal-state makes O(G) calls per active sync vs O(changed_groups) for legacy |
| Okta groups | Per-user `/users/{id}/groups` (O(users)) | Bulk `/groups` + `/groups/{id}/members` (O(groups)) | Minimal-state is cheaper when groups < users |
| AD | Same LDAP query pattern | Same | No difference |
| Jamf | Same REST pattern | Same | No difference |

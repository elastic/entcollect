// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package entraid

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"testing"
)

// BenchmarkDenseTopology_ScratchBackend exercises the bbolt-backed
// scratchBackend with a dense membership topology: 5k groups, each with
// 500 user members (2.5M total edges). Use this benchmark to evaluate
// memory and disk trade-offs when changing storage layout.
//
// Reported metrics:
//   - heap_delta_bytes: Go heap increase attributable to the graph
//   - rss_bytes: process RSS at peak (Linux only)
//   - scratch_file_bytes: size of the bbolt file on disk
//   - wall_time: handled by testing.B
func BenchmarkDenseTopology_ScratchBackend(b *testing.B) {
	const (
		nGroups         = 5000
		membersPerGroup = 500
		nUsers          = 50000
	)

	groups, membersByGroup := generateDenseFixture(nGroups, membersPerGroup, nUsers)
	userIDs := make([]string, nUsers)
	for i := range nUsers {
		userIDs[i] = fmt.Sprintf("u%d", i)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		func() {
			runtime.GC()
			var before runtime.MemStats
			runtime.ReadMemStats(&before)

			mg, err := newScratchBackend(b.TempDir())
			if err != nil {
				b.Fatal(err)
			}
			defer mg.close()

			for _, g := range groups {
				if err := mg.addGroup(g); err != nil {
					b.Fatal(err)
				}
				if err := mg.addMembers(g.ID, membersByGroup[g.ID]); err != nil {
					b.Fatal(err)
				}
			}

			for i := 0; i < 100; i++ {
				_, err := userTransitiveGroups(mg, userIDs[i%nUsers])
				if err != nil {
					b.Fatal(err)
				}
			}

			var after runtime.MemStats
			runtime.ReadMemStats(&after)

			b.ReportMetric(float64(after.HeapInuse-before.HeapInuse), "heap_delta_bytes")
			b.ReportMetric(float64(mg.db.Size()), "scratch_file_bytes")

			if rss := readRSS(); rss > 0 {
				b.ReportMetric(float64(rss), "rss_bytes")
			}
		}()
	}
}

// BenchmarkDenseTopology_MapBackend provides a baseline comparison using
// the in-memory mapBackend under the same dense topology.
func BenchmarkDenseTopology_MapBackend(b *testing.B) {
	const (
		nGroups         = 5000
		membersPerGroup = 500
		nUsers          = 50000
	)

	groups, membersByGroup := generateDenseFixture(nGroups, membersPerGroup, nUsers)
	userIDs := make([]string, nUsers)
	for i := range nUsers {
		userIDs[i] = fmt.Sprintf("u%d", i)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		runtime.GC()
		var before runtime.MemStats
		runtime.ReadMemStats(&before)

		mb := newMapBackend()
		for _, g := range groups {
			mb.addGroup(g)
			mb.addMembers(g.ID, membersByGroup[g.ID])
		}

		for i := 0; i < 100; i++ {
			userTransitiveGroups(mb, userIDs[i%nUsers])
		}

		var after runtime.MemStats
		runtime.ReadMemStats(&after)

		b.ReportMetric(float64(after.HeapInuse-before.HeapInuse), "heap_delta_bytes")

		if rss := readRSS(); rss > 0 {
			b.ReportMetric(float64(rss), "rss_bytes")
		}
	}
}

// generateDenseFixture creates a flat topology with nGroups groups, each
// containing membersPerGroup user members drawn from a pool of nUsers.
// No group nesting — exercises pure edge volume.
func generateDenseFixture(nGroups, membersPerGroup, nUsers int) ([]Group, map[string][]Member) {
	groups := make([]Group, nGroups)
	members := make(map[string][]Member, nGroups)
	for i := range nGroups {
		gid := fmt.Sprintf("g%d", i)
		groups[i] = Group{ID: gid, DisplayName: gid}
		ms := make([]Member, membersPerGroup)
		for j := range membersPerGroup {
			ms[j] = Member{
				ID:   fmt.Sprintf("u%d", (i*membersPerGroup+j)%nUsers),
				Type: odataTypeUser,
			}
		}
		members[gid] = ms
	}
	return groups, members
}

// readRSS reads the current process RSS from /proc/self/status on Linux.
// Returns 0 on non-Linux platforms.
func readRSS() int64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range splitLines(data) {
		if len(line) > 6 && string(line[:6]) == "VmRSS:" {
			fields := splitFields(line[6:])
			if len(fields) > 0 {
				kb, _ := strconv.ParseInt(string(fields[0]), 10, 64)
				return kb * 1024
			}
		}
	}
	return 0
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

func splitFields(line []byte) [][]byte {
	var fields [][]byte
	inField := false
	start := 0
	for i, b := range line {
		if b == ' ' || b == '\t' {
			if inField {
				fields = append(fields, line[start:i])
				inField = false
			}
		} else {
			if !inField {
				start = i
				inField = true
			}
		}
	}
	if inField {
		fields = append(fields, line[start:])
	}
	return fields
}

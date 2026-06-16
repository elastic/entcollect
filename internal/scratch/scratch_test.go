// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package scratch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenClose(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := db.Path()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("scratch file should exist at %s: %v", path, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("scratch file should be removed after Close, got err=%v", err)
	}
}

func TestOpenClose_DefaultDir(t *testing.T) {
	db, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	dir := filepath.Dir(db.Path())
	if dir != filepath.Clean(os.TempDir()) {
		t.Errorf("default dir = %s; want %s", dir, os.TempDir())
	}
}

func TestOpen_PredictablePrefix(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	base := filepath.Base(db.Path())
	if !strings.HasPrefix(base, filePrefix) {
		t.Errorf("file %s does not have prefix %s", base, filePrefix)
	}
}

func TestClose_Idempotent(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Errorf("second Close should not error, got %v", err)
	}
}

func TestClose_NilDB(t *testing.T) {
	var db *DB
	if err := db.Close(); err != nil {
		t.Errorf("Close on nil DB should not error, got %v", err)
	}
}

func TestPutGetJSON(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	type record struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}

	err = db.PutJSON("test", "k1", record{Name: "alice", Age: 30})
	if err != nil {
		t.Fatal(err)
	}

	var got record
	ok, err := db.GetJSON("test", "k1", &got)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected key to exist")
	}
	if got.Name != "alice" || got.Age != 30 {
		t.Errorf("got %+v; want {alice 30}", got)
	}
}

func TestGetJSON_NotFound(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	var got string
	ok, err := db.GetJSON("missing_bucket", "missing_key", &got)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected ok=false for missing key")
	}
}

func TestLinkNeighbors(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.Link("edges", "a", "b"); err != nil {
		t.Fatal(err)
	}
	if err := db.Link("edges", "a", "c"); err != nil {
		t.Fatal(err)
	}
	if err := db.Link("edges", "a", "d"); err != nil {
		t.Fatal(err)
	}

	got, err := db.Neighbors("edges", "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("Neighbors(a) = %v; want 3 elements", got)
	}

	set := make(map[string]bool, len(got))
	for _, v := range got {
		set[v] = true
	}
	for _, want := range []string{"b", "c", "d"} {
		if !set[want] {
			t.Errorf("missing neighbor %s in %v", want, got)
		}
	}
}

func TestNeighbors_NoEdges(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	got, err := db.Neighbors("edges", "nonexistent")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("expected nil for missing source, got %v", got)
	}
}

func TestNeighbors_MissingBucket(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	got, err := db.Neighbors("no_such_bucket", "key")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("expected nil for missing bucket, got %v", got)
	}
}

func TestLink_DuplicateEdge(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.Link("edges", "x", "y"); err != nil {
		t.Fatal(err)
	}
	if err := db.Link("edges", "x", "y"); err != nil {
		t.Fatal(err)
	}

	got, err := db.Neighbors("edges", "x")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "y" {
		t.Errorf("duplicate Link should be idempotent, got %v", got)
	}
}

func TestBatchLink(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	targets := []string{"t1", "t2", "t3", "t4", "t5"}
	if err := db.BatchLink("edges", "src", targets); err != nil {
		t.Fatal(err)
	}

	got, err := db.Neighbors("edges", "src")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(targets) {
		t.Fatalf("BatchLink: got %d neighbors; want %d", len(got), len(targets))
	}
}

func TestBatchLink_Empty(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.BatchLink("edges", "src", nil); err != nil {
		t.Fatal(err)
	}

	got, err := db.Neighbors("edges", "src")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("BatchLink(nil) should create no edges, got %v", got)
	}
}

func TestBatchWrite(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	type meta struct {
		Name string `json:"name"`
	}

	err = db.BatchWrite(func(tx *Tx) error {
		if err := tx.PutJSON("meta", "g1", meta{Name: "Group One"}); err != nil {
			return err
		}
		if err := tx.Link("members", "u1", "g1"); err != nil {
			return err
		}
		if err := tx.Link("members", "u2", "g1"); err != nil {
			return err
		}
		return tx.BatchLink("parents", "g1", []string{"p1", "p2"})
	})
	if err != nil {
		t.Fatal(err)
	}

	var m meta
	ok, err := db.GetJSON("meta", "g1", &m)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || m.Name != "Group One" {
		t.Errorf("PutJSON in BatchWrite: got %+v, ok=%v", m, ok)
	}

	n, err := db.Neighbors("members", "u1")
	if err != nil {
		t.Fatal(err)
	}
	if len(n) != 1 || n[0] != "g1" {
		t.Errorf("Link in BatchWrite: got %v; want [g1]", n)
	}

	parents, err := db.Neighbors("parents", "g1")
	if err != nil {
		t.Fatal(err)
	}
	if len(parents) != 2 {
		t.Errorf("BatchLink in BatchWrite: got %v; want [p1, p2]", parents)
	}
}

func TestSize(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	sz := db.Size()
	if sz <= 0 {
		t.Errorf("Size() = %d; want > 0", sz)
	}
}

func TestMultipleBuckets(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.Link("bucket_a", "x", "1"); err != nil {
		t.Fatal(err)
	}
	if err := db.Link("bucket_b", "x", "2"); err != nil {
		t.Fatal(err)
	}

	a, err := db.Neighbors("bucket_a", "x")
	if err != nil {
		t.Fatal(err)
	}
	b, err := db.Neighbors("bucket_b", "x")
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 1 || a[0] != "1" {
		t.Errorf("bucket_a neighbors = %v; want [1]", a)
	}
	if len(b) != 1 || b[0] != "2" {
		t.Errorf("bucket_b neighbors = %v; want [2]", b)
	}
}

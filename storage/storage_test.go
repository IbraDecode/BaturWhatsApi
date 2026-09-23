package storage

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKV(t *testing.T, kv KV) {
	t.Helper()
	ctx := context.Background()
	if _, err := kv.Get(ctx, "missing"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if err := kv.Set(ctx, "session/a/creds", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if err := kv.Set(ctx, "session/a/state", []byte("v2")); err != nil {
		t.Fatal(err)
	}
	if err := kv.Set(ctx, "session/b/creds", []byte("v3")); err != nil {
		t.Fatal(err)
	}
	got, err := kv.Get(ctx, "session/a/creds")
	if err != nil || !bytes.Equal(got, []byte("v1")) {
		t.Fatalf("get = %q %v", got, err)
	}
	keys, err := kv.List(ctx, "session/a/")
	if err != nil || len(keys) != 2 {
		t.Fatalf("list = %v %v", keys, err)
	}
	if keys[0] > keys[1] {
		t.Fatal("list not sorted")
	}
	if err := kv.Delete(ctx, "session/a/creds"); err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Get(ctx, "session/a/creds"); err != ErrNotFound {
		t.Fatal("delete failed")
	}
	if err := kv.Delete(ctx, "nonexistent"); err != nil {
		t.Fatalf("delete idempotent: %v", err)
	}
	// Weird keys must round-trip.
	weird := "meta/../../escape key\t\x00"
	if err := kv.Set(ctx, weird, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if g, err := kv.Get(ctx, weird); err != nil || string(g) != "x" {
		t.Fatalf("weird key: %q %v", g, err)
	}
}

func TestMemoryKV(t *testing.T) { testKV(t, NewMemory()) }

func TestFileKV(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	testKV(t, fs)
	// Persistence across reopen.
	if err := fs.Set(context.Background(), "durable", []byte("keep me")); err != nil {
		t.Fatal(err)
	}
	fs2, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	g, err := fs2.Get(context.Background(), "durable")
	if err != nil || string(g) != "keep me" {
		t.Fatalf("durable = %q err %v", g, err)
	}
	keys, _ := fs2.List(context.Background(), "session/")
	if len(keys) != 2 { // a/state and b/creds survived via manifest
		t.Fatalf("manifest rebuild lost keys: %v", keys)
	}
}

func TestFileEscapeSafety(t *testing.T) {
	dir := t.TempDir()
	fs, _ := NewFileStore(dir)
	if err := fs.Set(context.Background(), "../../etc/passwd", []byte("nope")); err != nil {
		t.Fatal(err)
	}
	keys, _ := fs.List(context.Background(), "")
	for _, k := range keys {
		if k == "../../etc/passwd" {
			continue // logical key intentionally preserved
		}
		t.Fatalf("unexpected key %q", k)
	}
	// All physical files must stay inside the base directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		full := filepath.Join(dir, name)
		rel, err := filepath.Rel(dir, full)
		if err != nil || rel == ".." || strings.HasPrefix(rel, "../") || name == ".." || strings.Contains(name, "/") {
			t.Fatalf("escaped file %q", name)
		}
	}
}

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashFileSHA256(t *testing.T) {
	t.Parallel()

	const expected = "65237497454f6f789d3dff68194878a89a6d01c65e6ffed33486ad09b8905850"

	path := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(path, []byte("WindoNetBlock\n"), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	actual, err := hashFileSHA256(path)
	if err != nil {
		t.Fatalf("hash test file: %v", err)
	}

	if actual != expected {
		t.Fatalf("unexpected SHA-256: got %q, want %q", actual, expected)
	}
}

func TestExecutableHashCacheReusesDigestForUnchangedFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(path, []byte("same content"), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	hashCalls := 0
	cache := newExecutableHashCache()
	cache.hash = func(string) (string, error) {
		hashCalls++
		return "cached-digest", nil
	}

	first, err := cache.SHA256(path)
	if err != nil {
		t.Fatalf("hash file first time: %v", err)
	}

	second, err := cache.SHA256(path)
	if err != nil {
		t.Fatalf("hash file second time: %v", err)
	}

	if first != "cached-digest" || second != "cached-digest" {
		t.Fatalf("unexpected cached digests: first %q, second %q", first, second)
	}

	if hashCalls != 1 {
		t.Fatalf("unexpected hash call count: got %d, want 1", hashCalls)
	}
}

func TestExecutableHashCacheRehashesChangedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(path, []byte("one"), 0o600); err != nil {
		t.Fatalf("write initial test file: %v", err)
	}

	hashCalls := 0
	cache := newExecutableHashCache()
	cache.hash = func(string) (string, error) {
		hashCalls++
		return "digest", nil
	}

	if _, err := cache.SHA256(path); err != nil {
		t.Fatalf("hash initial file: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat initial file: %v", err)
	}

	if err := os.WriteFile(path, []byte("changed content"), 0o600); err != nil {
		t.Fatalf("write changed test file: %v", err)
	}

	if err := os.Chtimes(
		path,
		info.ModTime().AddDate(0, 0, 1),
		info.ModTime().AddDate(0, 0, 1),
	); err != nil {
		t.Fatalf("change test file modification time: %v", err)
	}

	if _, err := cache.SHA256(path); err != nil {
		t.Fatalf("hash changed file: %v", err)
	}

	if hashCalls != 2 {
		t.Fatalf("unexpected hash call count: got %d, want 2", hashCalls)
	}
}

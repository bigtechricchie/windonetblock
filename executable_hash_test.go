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

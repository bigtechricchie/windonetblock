package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExecutableFileIdentityString(t *testing.T) {
	t.Parallel()

	identity := ExecutableFileIdentity{
		VolumeSerialNumber: 0x0123456789ABCDEF,
		FileID: [16]byte{
			0x00, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77,
			0x88, 0x99, 0xAA, 0xBB,
			0xCC, 0xDD, 0xEE, 0xFF,
		},
	}

	const expected = "volume=0123456789ABCDEF file=00112233445566778899aabbccddeeff"

	if actual := identity.String(); actual != expected {
		t.Fatalf("unexpected identity: got %q, want %q", actual, expected)
	}
}

func TestExecutableFileIdentityStableForSameFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "sample.exe")
	if err := os.WriteFile(path, []byte("WindoNetBlock"), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	first, err := executableFileIdentity(path)
	if err != nil {
		t.Fatalf("query first file identity: %v", err)
	}

	second, err := executableFileIdentity(path)
	if err != nil {
		t.Fatalf("query second file identity: %v", err)
	}

	if first != second {
		t.Fatalf("file identity changed: first %#v, second %#v", first, second)
	}
}

func TestExecutableFileStateChangesWhenFileContentChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.exe")
	if err := os.WriteFile(path, []byte("one"), 0o600); err != nil {
		t.Fatalf("write initial test file: %v", err)
	}

	before, err := executableFileState(path)
	if err != nil {
		t.Fatalf("query initial file state: %v", err)
	}

	if err := os.WriteFile(path, []byte("changed content"), 0o600); err != nil {
		t.Fatalf("write changed test file: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat changed file: %v", err)
	}

	if err := os.Chtimes(
		path,
		info.ModTime().AddDate(0, 0, 1),
		info.ModTime().AddDate(0, 0, 1),
	); err != nil {
		t.Fatalf("change test file modification time: %v", err)
	}

	after, err := executableFileState(path)
	if err != nil {
		t.Fatalf("query changed file state: %v", err)
	}

	if before == after {
		t.Fatal("file state did not change after file content changed")
	}
}

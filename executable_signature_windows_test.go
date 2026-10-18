package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyAuthenticodeStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode uint32
		want       ExecutableSignatureStatus
	}{
		{
			name:       "trusted",
			statusCode: 0,
			want:       SignatureTrusted,
		},
		{
			name:       "unsigned",
			statusCode: trustENoSignature,
			want:       SignatureUnsigned,
		},
		{
			name:       "other trust failure",
			statusCode: 0x800B0004,
			want:       SignatureNotTrusted,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := classifyAuthenticodeStatus(test.statusCode)
			if got != test.want {
				t.Fatalf("unexpected status: got %q, want %q", got, test.want)
			}
		})
	}
}

func TestExecutableSignatureCacheReusesEvidenceForUnchangedFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "sample.exe")
	if err := os.WriteFile(path, []byte("same content"), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	verifyCalls := 0
	cache := newExecutableSignatureCache()
	cache.verify = func(string) (ExecutableSignatureEvidence, error) {
		verifyCalls++
		return ExecutableSignatureEvidence{
			Status:     SignatureUnsigned,
			StatusCode: trustENoSignature,
		}, nil
	}

	first, err := cache.Verify(path)
	if err != nil {
		t.Fatalf("verify file first time: %v", err)
	}

	second, err := cache.Verify(path)
	if err != nil {
		t.Fatalf("verify file second time: %v", err)
	}

	if first != second {
		t.Fatalf("unexpected cached evidence: first %#v, second %#v", first, second)
	}

	if verifyCalls != 1 {
		t.Fatalf("unexpected verify call count: got %d, want 1", verifyCalls)
	}
}

func TestExecutableSignatureCacheReverifiesChangedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.exe")
	if err := os.WriteFile(path, []byte("one"), 0o600); err != nil {
		t.Fatalf("write initial test file: %v", err)
	}

	verifyCalls := 0
	cache := newExecutableSignatureCache()
	cache.verify = func(string) (ExecutableSignatureEvidence, error) {
		verifyCalls++
		return ExecutableSignatureEvidence{
			Status:     SignatureUnsigned,
			StatusCode: trustENoSignature,
		}, nil
	}

	if _, err := cache.Verify(path); err != nil {
		t.Fatalf("verify initial file: %v", err)
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

	if _, err := cache.Verify(path); err != nil {
		t.Fatalf("verify changed file: %v", err)
	}

	if verifyCalls != 2 {
		t.Fatalf("unexpected verify call count: got %d, want 2", verifyCalls)
	}
}

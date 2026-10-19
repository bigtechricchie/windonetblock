package main

import (
	"syscall"
	"testing"
	"time"
)

func TestFiletimeToUTC(t *testing.T) {
	t.Parallel()

	expected := time.Date(
		2026,
		time.October,
		19,
		12,
		34,
		56,
		789000000,
		time.UTC,
	)

	filetime := syscall.NsecToFiletime(expected.UnixNano())
	actual := filetimeToUTC(filetime)

	if !actual.Equal(expected) {
		t.Fatalf("unexpected time: got %s, want %s", actual, expected)
	}

	if actual.Location() != time.UTC {
		t.Fatalf("unexpected location: got %v, want UTC", actual.Location())
	}
}

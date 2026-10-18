package main

import "testing"

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

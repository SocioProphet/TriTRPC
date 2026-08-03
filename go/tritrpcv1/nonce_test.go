package tritrpcv1

import (
	"bytes"
	"testing"
)

// TestDeriveNonceMatchesFrameLane: the derivation equals the frame lane's "TRPC"||seq construction.
func TestDeriveNonceMatchesFrameLane(t *testing.T) {
	n, err := DeriveNonce([]byte("TRPC"), 18)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte("TRPC"), 0, 0, 0, 0, 0, 0, 0, 18)
	if !bytes.Equal(n, want) || len(n) != 12 {
		t.Fatalf("DeriveNonce mismatch: got %v", n)
	}
	if _, err := DeriveNonce([]byte("TRP"), 1); err == nil {
		t.Fatal("a non-4-byte context prefix must be refused")
	}
}

// TestNonceLedgerFailClosed: reuse / non-monotonic refused within a session; cross-session ok.
func TestNonceLedgerFailClosed(t *testing.T) {
	l := NewNonceLedger()
	if _, err := l.Issue([]byte("SESA"), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Issue([]byte("SESA"), 2); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Issue([]byte("SESA"), 2); err == nil {
		t.Fatal("reused sequence must be refused")
	}
	if _, err := l.Issue([]byte("SESA"), 1); err == nil {
		t.Fatal("non-monotonic sequence must be refused")
	}
	if _, err := l.Issue([]byte("SESB"), 1); err != nil {
		t.Fatal("same seq under a different session must be allowed")
	}
}

package tritrpcv1

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// oraclePath locates the shared Python-generated parity vectors.
func oraclePath() string {
	return filepath.Join("..", "..", "reference", "experimental",
		"tritrpc_requirements_impl_v4", "generated", "sample_vectors_v4.json")
}

// TestState243MatchesOracle: the canonical State243 (active/verified/routine/fluid/cohort) encodes
// to the exact byte the Python oracle records (recompute-don't-trust against the shared vector).
func TestState243MatchesOracle(t *testing.T) {
	data, err := os.ReadFile(oraclePath())
	if err != nil {
		t.Fatalf("read oracle: %v", err)
	}
	var vec map[string]json.RawMessage
	if err := json.Unmarshal(data, &vec); err != nil {
		t.Fatalf("parse oracle: %v", err)
	}
	var want uint8
	if err := json.Unmarshal(vec["state243"], &want); err != nil {
		t.Fatalf("oracle state243: %v", err)
	}
	// active=1, verified=2, routine=0, fluid=0, cohort=1
	got, err := State243{Lifecycle: 1, Epistemic: 2, Novelty: 0, Friction: 0, Scope: 1}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("State243 parity: got %d, oracle %d", got, want)
	}
}

// TestControlAndStateRoundtripAll: every value 0..242 round-trips through both primitives.
func TestControlAndStateRoundtripAll(t *testing.T) {
	for v := 0; v <= 242; v++ {
		c, err := DecodeControl243(uint8(v))
		if err != nil {
			t.Fatalf("decode control %d: %v", v, err)
		}
		if enc, _ := c.Encode(); enc != uint8(v) {
			t.Fatalf("control roundtrip %d -> %d", v, enc)
		}
		s, err := DecodeState243(uint8(v))
		if err != nil {
			t.Fatalf("decode state %d: %v", v, err)
		}
		if enc, _ := s.Encode(); enc != uint8(v) {
			t.Fatalf("state roundtrip %d -> %d", v, enc)
		}
	}
}

// TestNonTritRejected: a non-canonical field (>2) is refused (fail-closed).
func TestNonTritRejected(t *testing.T) {
	if _, err := (State243{Lifecycle: 3}).Encode(); err == nil {
		t.Fatal("expected non-trit State243 field to be rejected")
	}
	if _, err := (Control243{Profile: 5}).Encode(); err == nil {
		t.Fatal("expected non-trit Control243 field to be rejected")
	}
	if _, err := DecodeState243(243); err == nil {
		t.Fatal("expected out-of-range byte to be rejected")
	}
}

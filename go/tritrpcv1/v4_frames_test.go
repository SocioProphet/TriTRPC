package tritrpcv1

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func frameOracle(t *testing.T) map[string]json.RawMessage {
	p := filepath.Join("..", "..", "reference", "experimental",
		"tritrpc_requirements_impl_v4", "generated", "sample_vectors_v4.json")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read oracle: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse oracle: %v", err)
	}
	return m
}

func oracleHex(t *testing.T, m map[string]json.RawMessage, k string) string {
	var s string
	if err := json.Unmarshal(m[k], &s); err != nil {
		t.Fatalf("oracle %s: %v", k, err)
	}
	return s
}

// TestHotUnaryFrameMatchesOracle: the CLI hot frame serializes byte-identical to the oracle vector
// (control=1, kind=UNARY_REQ, suite=FIPS_CLASSICAL, epoch=18, route=7, payload, seq=1, demo key).
func TestHotUnaryFrameMatchesOracle(t *testing.T) {
	m := frameOracle(t)
	f := HotUnaryFrame{
		Control:     Control243{Profile: 0, Lane: 0, Evidence: 0, Fallback: 0, RouteFmt: 1},
		Suite:       SuiteFIPSClassical,
		Kind:        KindUnaryReq,
		Epoch:       18,
		RouteHandle: 7,
		Payload:     []byte(`{"op":"add-vertex","id":"a"}`),
		Sequence:    1,
	}
	got, err := f.Serialize(DemoKey())
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != oracleHex(t, m, "hot_unary") {
		t.Fatalf("hot_unary parity:\n got %s\n want %s", hex.EncodeToString(got), oracleHex(t, m, "hot_unary"))
	}
}

// TestBeaconCommitFrameMatchesOracle: the CLI beacon commit serializes byte-identical to the oracle.
// beacon payload = [State243.encode()==136] + beacon_identity string; control all-2s (=242),
// suite=CNSA2, epoch=18, identity_handle=19, phase=4, topic=21, seq=4.
func TestBeaconCommitFrameMatchesOracle(t *testing.T) {
	m := frameOracle(t)
	state243 := byte(136) // State243(active,verified,routine,fluid,cohort)
	payload := append([]byte{state243}, []byte(oracleHex(t, m, "beacon_identity"))...)
	f := BeaconFrame{
		Control:        Control243{Profile: 2, Lane: 2, Evidence: 2, Fallback: 2, RouteFmt: 2},
		Suite:          SuiteCNSA2Ready,
		Kind:           KindBeaconCommit,
		Epoch:          18,
		IdentityHandle: 19,
		Phase:          4,
		Topic:          21,
		Payload:        payload,
		Sequence:       4,
	}
	got, err := f.Serialize(DemoKey())
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != oracleHex(t, m, "beacon_commit") {
		t.Fatalf("beacon_commit parity:\n got %s\n want %s", hex.EncodeToString(got), oracleHex(t, m, "beacon_commit"))
	}
}

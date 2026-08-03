package tritrpcv1

import (
	"encoding/hex"
	"testing"
)

// ctrlA is the shared control byte used by the CLI stream frames (path_a/classical/exact/none/handle).
func ctrlA() Control243 { return Control243{Profile: 0, Lane: 0, Evidence: 0, Fallback: 0, RouteFmt: 1} }

// TestStreamOpenInheritedMatchesOracle: default semantic pair (braid 101, state 136), seq 2.
func TestStreamOpenInheritedMatchesOracle(t *testing.T) {
	m := frameOracle(t)
	f := StreamOpenFrame{
		Control: ctrlA(), Suite: SuiteFIPSClassical, Kind: KindStreamOpen, Epoch: 18,
		RouteHandle: 7, StreamID: 9, Payload: []byte(`{"cursor":"start"}`),
		DefaultBraid: SemanticPair{Set: true, Braid: 101, State: 136}, Sequence: 2,
	}
	got, err := f.Serialize(DemoKey())
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != oracleHex(t, m, "stream_open_inherited") {
		t.Fatalf("stream_open parity:\n got %s\n want %s", hex.EncodeToString(got), oracleHex(t, m, "stream_open_inherited"))
	}
}

// TestStreamDataInheritMatchesOracle: no override (empty semantic pair), seq 3.
func TestStreamDataInheritMatchesOracle(t *testing.T) {
	m := frameOracle(t)
	f := StreamDataFrame{
		Control: ctrlA(), Suite: SuiteFIPSClassical, Epoch: 18, StreamID: 9,
		Payload: []byte(`{"chunk":1}`), Sequence: 3,
	}
	got, _ := f.Serialize(DemoKey())
	if hex.EncodeToString(got) != oracleHex(t, m, "stream_data_inherit") {
		t.Fatalf("stream_data_inherit parity:\n got %s\n want %s", hex.EncodeToString(got), oracleHex(t, m, "stream_data_inherit"))
	}
}

// TestStreamDataOverrideMatchesOracle: override semantic pair (101,136), seq 30.
func TestStreamDataOverrideMatchesOracle(t *testing.T) {
	m := frameOracle(t)
	f := StreamDataFrame{
		Control: ctrlA(), Suite: SuiteFIPSClassical, Epoch: 18, StreamID: 9,
		Payload: []byte(`{"chunk":1}`), Override: SemanticPair{Set: true, Braid: 101, State: 136}, Sequence: 30,
	}
	got, _ := f.Serialize(DemoKey())
	if hex.EncodeToString(got) != oracleHex(t, m, "stream_data_override") {
		t.Fatalf("stream_data_override parity:\n got %s\n want %s", hex.EncodeToString(got), oracleHex(t, m, "stream_data_override"))
	}
}

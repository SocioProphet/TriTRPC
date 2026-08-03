package tritrpcv1

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func codecVectorsPath() string {
	return filepath.Join("..", "..", "fixtures", "v4", "codec_primitive_vectors.json")
}

type codecVectors struct {
	S243 []struct {
		V   uint64 `json:"v"`
		Hex string `json:"hex"`
	} `json:"s243"`
	Handle243 []struct {
		Kind string `json:"kind"`
		V    any    `json:"v"`
		Hex  string `json:"hex"`
	} `json:"handle243"`
	Braid243 []struct {
		Phase uint8 `json:"phase"`
		Topic uint8 `json:"topic"`
		Byte  uint8 `json:"byte"`
	} `json:"braid243"`
}

func loadCodecVectors(t *testing.T) codecVectors {
	data, err := os.ReadFile(codecVectorsPath())
	if err != nil {
		t.Fatalf("read oracle vectors: %v", err)
	}
	var v codecVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse oracle vectors: %v", err)
	}
	return v
}

// TestS243MatchesOracle: encode + round-trip against the Python oracle bytes.
func TestS243MatchesOracle(t *testing.T) {
	for _, c := range loadCodecVectors(t).S243 {
		got := hex.EncodeToString(EncodeS243(c.V))
		if got != c.Hex {
			t.Fatalf("S243(%d): got %s, oracle %s", c.V, got, c.Hex)
		}
		v, off, err := DecodeS243(EncodeS243(c.V), 0)
		if err != nil || v != c.V || off != len(EncodeS243(c.V)) {
			t.Fatalf("S243 roundtrip %d: v=%d off=%d err=%v", c.V, v, off, err)
		}
	}
}

// TestBraid243MatchesOracle: encode == oracle byte, round-trip, and reserved-coordinate rejection.
func TestBraid243MatchesOracle(t *testing.T) {
	for _, c := range loadCodecVectors(t).Braid243 {
		got, err := EncodeBraid243(c.Phase, c.Topic)
		if err != nil || got != c.Byte {
			t.Fatalf("Braid243(%d,%d): got %d oracle %d err=%v", c.Phase, c.Topic, got, c.Byte, err)
		}
		p, tp, err := DecodeBraid243(got)
		if err != nil || p != c.Phase || tp != c.Topic {
			t.Fatalf("Braid243 roundtrip: %d,%d -> %d,%d", c.Phase, c.Topic, p, tp)
		}
	}
	if _, _, err := DecodeBraid243(242); err == nil { // reserved (phaseCode=8)
		t.Fatal("expected reserved Braid243 coordinate to be rejected")
	}
	if _, err := EncodeBraid243(8, 1); err == nil {
		t.Fatal("expected out-of-range phase to be rejected")
	}
}

// TestHandle243MatchesOracle: each variant encodes to the exact oracle bytes and round-trips.
func TestHandle243MatchesOracle(t *testing.T) {
	for _, c := range loadCodecVectors(t).Handle243 {
		var h Handle243
		switch c.Kind {
		case "int":
			h = Handle243{Kind: HandleDirect, Direct: uint8(c.V.(float64))}
		case "ext":
			h = Handle243{Kind: HandleExt, Ext: uint64(c.V.(float64))}
		case "str":
			h = Handle243{Kind: HandleStr, Str: c.V.(string)}
		case "hash":
			var b [32]byte
			raw, _ := hex.DecodeString(c.V.(string))
			copy(b[:], raw)
			h = Handle243{Kind: HandleHash, Hash: b}
		case "tombstone":
			h = Handle243{Kind: HandleTombstone}
		}
		enc, err := EncodeHandle243(h)
		if err != nil {
			t.Fatalf("encode handle %s: %v", c.Kind, err)
		}
		if hex.EncodeToString(enc) != c.Hex {
			t.Fatalf("Handle243 %s: got %s oracle %s", c.Kind, hex.EncodeToString(enc), c.Hex)
		}
		dec, off, err := DecodeHandle243(enc, 0)
		if err != nil || off != len(enc) || dec.Kind != h.Kind {
			t.Fatalf("Handle243 %s roundtrip: off=%d kind=%d err=%v", c.Kind, off, dec.Kind, err)
		}
	}
}

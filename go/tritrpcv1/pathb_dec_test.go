package tritrpcv1

import "testing"

// TestPBDecodeLenRoundtrip: a valid Path-B length (encoded via the shared TLEB3 lane) decodes back.
func TestPBDecodeLenRoundtrip(t *testing.T) {
	for _, v := range []uint64{0, 1, 8, 80, 1000} {
		enc := TLEB3EncodeLen(v)
		got, off, err := PBDecodeLen(enc, 0)
		if err != nil {
			t.Fatalf("PBDecodeLen(%d) errored: %v", v, err)
		}
		if uint64(got) != v || off != len(enc) {
			t.Fatalf("PBDecodeLen(%d): got %d off %d (enc %d bytes)", v, got, off, len(enc))
		}
	}
}

// TestPBHardenedFailClosed: malformed inputs return errors and NEVER panic (the gap #6 fix).
func TestPBHardenedFailClosed(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("hardened Path-B decoder panicked on malformed input: %v", r)
		}
	}()
	// offset past end
	if _, _, err := PBDecodeLen([]byte{}, 0); err == nil {
		t.Fatal("empty buffer must error")
	}
	if _, _, err := PBDecodeLen([]byte{0x01}, 5); err == nil {
		t.Fatal("offset past end must error")
	}
	// truncated tail marker (243..246 with no following byte)
	if _, _, err := PBDecodeLen([]byte{243}, 0); err == nil {
		t.Fatal("truncated tail marker must error")
	}
	// a run with no terminator (all-continuation-ish garbage) must be refused, not loop forever
	garbage := make([]byte, 400)
	for i := range garbage {
		garbage[i] = 242
	}
	if _, _, err := PBDecodeLen(garbage, 0); err == nil {
		t.Fatal("over-long / no-terminator run must be refused")
	}
	// string with a declared length longer than the remaining buffer
	enc := TLEB3EncodeLen(100) // says "100 bytes follow" but buffer is short
	if _, _, err := PBDecodeString(enc, 0); err == nil {
		t.Fatal("over-long declared string length must error (no OOB slice)")
	}
}

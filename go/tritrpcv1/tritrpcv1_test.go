package tritrpcv1

import "testing"

func TestMicroVectors(t *testing.T) {
	b := TritPack243([]byte{2, 1, 0, 0, 2})
	if len(b) != 1 || b[0] != 0xBF {
		t.Fatalf("pack fail, got %x", b)
	}
	b2 := TritPack243([]byte{2, 2, 1})
	if len(b2) != 2 || b2[0] != 0xF5 || b2[1] != 0x19 {
		t.Fatalf("tail fail, got %x", b2)
	}
}

func TestTleb3EncodeLen(t *testing.T) {
	for _, n := range []uint64{0, 1, 2, 3, 8, 9, 10, 123, 4096, 65535} {
		enc := TLEB3EncodeLen(n)
		if len(enc) == 0 {
			t.Fatalf("empty encoding for %d", n)
		}
	}
}

func TestTLEB3DecodeLenTailMarker(t *testing.T) {
	// Verify that tail-marker lengths decode correctly and newOff accounts for all bytes
	cases := []struct {
		name    string
		buf     []byte
		offset  int
		wantV   uint64
		wantOff int
	}{
		{"len=0", []byte{0xF5, 0x00}, 0, 0, 2},         // [0,0,0] tail marker → 0
		{"len=2", []byte{0xF5, 0x02}, 0, 2, 2},         // [0,0,2] tail marker → 2
		{"len=32", []byte{0xD0, 0xF3, 0x00}, 0, 32, 3}, // 5+1 trits spanning regular+tail
		{"len=9", []byte{0xA2, 0xF3, 0x01}, 0, 9, 3},   // 9 spans tail marker
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, no, err := TLEB3DecodeLen(c.buf, c.offset)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if v != c.wantV {
				t.Errorf("value: got %d, want %d", v, c.wantV)
			}
			if no != c.wantOff {
				t.Errorf("newOff: got %d, want %d", no, c.wantOff)
			}
		})
	}
}

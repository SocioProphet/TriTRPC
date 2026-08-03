package tritrpcv1

import (
	"errors"
	"fmt"
)

// Path-B (ternary-native) decoders. Hardened, fail-closed scanner (vNext gap #6): every read is
// bounds-checked and every malformed input returns an error instead of panicking or reading out of
// bounds, so Path-B can safely take larger wire responsibility. Subset used in fixtures: length,
// string, union index.

// maxPBLenTrits caps the scan so adversarial input without a terminator cannot loop unbounded.
const maxPBLenTrits = 640 // >> any real length; a Path-B length that needs more is rejected

// PBDecodeLen decodes a ternary-native length starting at off. Fail-closed: truncation, a missing
// terminator, or an over-long run returns an error (never panics / reads out of bounds).
func PBDecodeLen(buf []byte, off int) (val int, newOff int, err error) {
	if off < 0 || off >= len(buf) {
		return 0, 0, errors.New("path-b length: offset past end of buffer")
	}
	trits := make([]byte, 0, 16)
	start := off
	for {
		if off >= len(buf) {
			return 0, 0, errors.New("path-b length: truncated (no terminator before end of buffer)")
		}
		b := buf[off]
		var ts []byte
		var e error
		if b >= 243 && b <= 246 {
			if off+1 >= len(buf) {
				return 0, 0, errors.New("path-b length: truncated tail marker")
			}
			ts, e = TritUnpack243(buf[off : off+2])
			off += 2
		} else {
			ts, e = TritUnpack243([]byte{b})
			off++
		}
		if e != nil {
			return 0, 0, fmt.Errorf("path-b length: bad trit group: %w", e)
		}
		trits = append(trits, ts...)
		if len(trits) > maxPBLenTrits {
			return 0, 0, errors.New("path-b length: over-long run (no terminator) — refused")
		}
		if len(trits) >= 3 {
			v := uint64(0)
			used := 0
			for j := 0; j < len(trits)/3; j++ {
				c, p1, p0 := trits[3*j], trits[3*j+1], trits[3*j+2]
				digit := uint64(p1)*3 + uint64(p0)
				mul := uint64(1)
				for k := 0; k < j; k++ {
					mul *= 9
				}
				v += digit * mul
				if c == 0 {
					used = (j + 1) * 3
					break
				}
			}
			if used > 0 {
				usedBytes := len(TritPack243(trits[:used]))
				return int(v), start + usedBytes, nil
			}
		}
	}
}

// PBDecodeString decodes a length-prefixed Path-B string. Fail-closed: a declared length that would
// run past the buffer is rejected (no out-of-bounds slice).
func PBDecodeString(buf []byte, off int) (string, int, error) {
	l, o2, err := PBDecodeLen(buf, off)
	if err != nil {
		return "", 0, err
	}
	if l < 0 || o2 > len(buf) || l > len(buf)-o2 {
		return "", 0, fmt.Errorf("path-b string: declared length %d exceeds %d remaining bytes", l, len(buf)-o2)
	}
	return string(buf[o2 : o2+l]), o2 + l, nil
}

// PBDecodeUnionIndex decodes a Path-B union index (a bare length), bounds-checked.
func PBDecodeUnionIndex(buf []byte, off int) (int, int, error) {
	return PBDecodeLen(buf, off)
}

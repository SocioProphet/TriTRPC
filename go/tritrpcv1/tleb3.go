package tritrpcv1

import "errors"

func TLEB3EncodeLen(n uint64) []byte {
	var digits []byte
	if n == 0 {
		digits = []byte{0}
	} else {
		for n > 0 {
			digits = append(digits, byte(n%9))
			n /= 9
		}
	}
	var trits []byte
	for i, d := range digits {
		c := byte(0)
		if i < len(digits)-1 {
			c = 2
		}
		p1 := d / 3
		p0 := d % 3
		trits = append(trits, c, p1, p0)
	}
	return TritPack243(trits)
}

func TLEB3DecodeLen(buf []byte, offset int) (val uint64, newOff int, err error) {
	trits := []byte{}
	pos := offset
	for {
		if pos >= len(buf) {
			return 0, 0, errors.New("EOF in TLEB3")
		}
		b := buf[pos]
		pos++
		var ts []byte
		// Tail-marker bytes (0xF3..=0xF6) span two bytes; pass both to TritUnpack243.
		if b >= 0xF3 && b <= 0xF6 {
			if pos >= len(buf) {
				return 0, 0, errors.New("truncated TLEB3 tail marker")
			}
			b2 := buf[pos]
			pos++
			ts, err = TritUnpack243([]byte{b, b2})
		} else {
			ts, err = TritUnpack243([]byte{b})
		}
		if err != nil {
			return 0, 0, err
		}
		trits = append(trits, ts...)
		if len(trits) < 3 {
			continue
		}
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
			pack := TritPack243(trits[:used])
			return v, offset + len(pack), nil
		}
	}
}

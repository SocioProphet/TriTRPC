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
		if b >= 243 && b <= 246 {
			if pos >= len(buf) {
				return 0, 0, errors.New("truncated TLEB3 tail marker")
			}
			ts, _ = TritUnpack243([]byte{b, buf[pos]})
			pos++
		} else {
			ts, _ = TritUnpack243([]byte{b})
		}
		b := buf[off]
		readCount := 1
		if b >= 243 && b <= 246 {
			readCount = 2
		}
		if off+readCount > len(buf) {
			return 0, 0, errors.New("EOF in TLEB3")
		}
		ts, e := TritUnpack243(buf[off : off+readCount])
		if e != nil {
			return 0, 0, e
		}
		off += readCount
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
			usedBytes := len(pack)
			return v, offset + usedBytes, nil
		}
	}
}

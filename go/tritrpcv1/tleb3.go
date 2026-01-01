
package tritrpcv1

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

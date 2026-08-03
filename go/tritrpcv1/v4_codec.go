package tritrpcv1

// v4 codec primitives — Go port, byte-identical to the Python oracle
// (reference/experimental/.../codec.py, naming.py). No crypto: pure canonical encodings.
//   S243     : a value in 0..242 is one byte; larger values are [243] + TLEB3(value-243).
//   Handle243: 0..242 direct; [243]+S243(ext_id); [244]+S243(len)+utf8; [245]+32B hash; [246] tombstone.
//   Braid243 : (phase 1..7, topic 1..23) -> (phase-1)*27 + (topic-1), a single byte in 0..188.

import (
	"errors"
	"fmt"
)

// EncodeS243 encodes a non-negative integer per the canonical S243 form.
func EncodeS243(value uint64) []byte {
	if value <= 242 {
		return []byte{byte(value)}
	}
	return append([]byte{243}, TLEB3EncodeLen(value-243)...)
}

// DecodeS243 inverts EncodeS243, returning the value and the new offset.
func DecodeS243(data []byte, offset int) (uint64, int, error) {
	if offset >= len(data) {
		return 0, 0, errors.New("EOF in S243")
	}
	prefix := data[offset]
	if prefix <= 242 {
		return uint64(prefix), offset + 1, nil
	}
	if prefix != 243 {
		return 0, 0, errors.New("invalid leading byte for canonical S243")
	}
	v, newOff, err := TLEB3DecodeLen(data, offset+1)
	if err != nil {
		return 0, 0, err
	}
	return 243 + v, newOff, nil
}

// EncodeBraid243 packs a (phase 1..7, topic 1..23) braided coordinate into one byte.
func EncodeBraid243(phase, topic uint8) (uint8, error) {
	if phase < 1 || phase > 7 {
		return 0, errors.New("phase must be in 1..7 for Braid243")
	}
	if topic < 1 || topic > 23 {
		return 0, errors.New("topic must be in 1..23 for Braid243")
	}
	return (phase-1)*27 + (topic - 1), nil
}

// DecodeBraid243 inverts EncodeBraid243.
func DecodeBraid243(value uint8) (phase, topic uint8, err error) {
	if value > 242 {
		return 0, 0, errors.New("Braid243 byte must be in 0..242")
	}
	phaseCode := value / 27
	topicCode := value % 27
	if phaseCode > 6 || topicCode > 22 {
		return 0, 0, errors.New("reserved Braid243 coordinate")
	}
	return phaseCode + 1, topicCode + 1, nil
}

// HandleKind tags a Handle243 variant.
type HandleKind int

const (
	HandleDirect HandleKind = iota
	HandleExt
	HandleStr
	HandleHash
	HandleTombstone
)

// Handle243 is a route-handle value (one of five canonical variants).
type Handle243 struct {
	Kind   HandleKind
	Direct uint8    // HandleDirect: 0..242
	Ext    uint64   // HandleExt
	Str    string   // HandleStr
	Hash   [32]byte // HandleHash
}

// EncodeHandle243 serializes a Handle243, byte-identical to the oracle.
func EncodeHandle243(h Handle243) ([]byte, error) {
	switch h.Kind {
	case HandleDirect:
		if h.Direct > 242 {
			return nil, errors.New("direct Handle243 values must be in 0..242")
		}
		return []byte{h.Direct}, nil
	case HandleExt:
		return append([]byte{243}, EncodeS243(h.Ext)...), nil
	case HandleStr:
		raw := []byte(h.Str)
		out := append([]byte{244}, EncodeS243(uint64(len(raw)))...)
		return append(out, raw...), nil
	case HandleHash:
		return append([]byte{245}, h.Hash[:]...), nil
	case HandleTombstone:
		return []byte{246}, nil
	default:
		return nil, fmt.Errorf("unsupported Handle243 kind: %d", h.Kind)
	}
}

// DecodeHandle243 inverts EncodeHandle243.
func DecodeHandle243(data []byte, offset int) (Handle243, int, error) {
	if offset >= len(data) {
		return Handle243{}, 0, errors.New("EOF in Handle243")
	}
	prefix := data[offset]
	switch {
	case prefix <= 242:
		return Handle243{Kind: HandleDirect, Direct: prefix}, offset + 1, nil
	case prefix == 243:
		v, newOff, err := DecodeS243(data, offset+1)
		if err != nil {
			return Handle243{}, 0, err
		}
		return Handle243{Kind: HandleExt, Ext: v}, newOff, nil
	case prefix == 244:
		n, newOff, err := DecodeS243(data, offset+1)
		if err != nil {
			return Handle243{}, 0, err
		}
		end := newOff + int(n)
		if end > len(data) {
			return Handle243{}, 0, errors.New("truncated inline UTF-8 handle")
		}
		return Handle243{Kind: HandleStr, Str: string(data[newOff:end])}, end, nil
	case prefix == 245:
		end := offset + 1 + 32
		if end > len(data) {
			return Handle243{}, 0, errors.New("truncated hash handle")
		}
		var h [32]byte
		copy(h[:], data[offset+1:end])
		return Handle243{Kind: HandleHash, Hash: h}, end, nil
	case prefix == 246:
		return Handle243{Kind: HandleTombstone}, offset + 1, nil
	default:
		return Handle243{}, 0, errors.New("invalid Handle243 prefix")
	}
}

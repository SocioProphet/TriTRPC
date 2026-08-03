package tritrpcv1

// v4 stream frames — Go port, byte-identical to the Python oracle (frames.py). StreamOpen carries a
// route handle + stream id + an optional DEFAULT semantic pair (Braid243, State243); StreamData
// carries a stream id + an optional OVERRIDE semantic pair; StreamClose carries a stream id. The
// semantic pair is two bytes [braid, state] when present, or empty when absent (both-or-neither).
// Same AEAD tag lane as the other frames (AES-256-GCM over the prefix).

// SemanticPair is an optional (Braid243, State243) coordinate; Set=false means "no pair".
type SemanticPair struct {
	Set   bool
	Braid uint8 // 0..188 (from EncodeBraid243)
	State uint8 // 0..242 (State243.Encode)
}

func encodeSemanticPair(p SemanticPair) []byte {
	if !p.Set {
		return nil
	}
	return []byte{p.Braid, p.State}
}

// StreamOpenFrame opens a stream, optionally establishing default semantics.
type StreamOpenFrame struct {
	Control      Control243
	Suite        CryptoSuite
	Kind         FrameKind
	Epoch        uint64
	RouteHandle  uint8
	StreamID     uint64
	Payload      []byte
	DefaultBraid SemanticPair
	Sequence     uint64
}

func (f StreamOpenFrame) prefix() ([]byte, error) {
	cb, err := f.Control.Encode()
	if err != nil {
		return nil, err
	}
	h, err := EncodeHandle243(Handle243{Kind: HandleDirect, Direct: f.RouteHandle})
	if err != nil {
		return nil, err
	}
	out := append([]byte{}, v4Magic...)
	out = append(out, cb, byte(f.Kind), byte(f.Suite))
	out = append(out, EncodeS243(f.Epoch)...)
	out = append(out, h...)
	out = append(out, EncodeS243(f.StreamID)...)
	out = append(out, EncodeS243(uint64(len(f.Payload)))...)
	out = append(out, f.Payload...)
	out = append(out, encodeSemanticPair(f.DefaultBraid)...)
	return out, nil
}

// Serialize builds the wire frame (prefix + AES-256-GCM tag).
func (f StreamOpenFrame) Serialize(key []byte) ([]byte, error) {
	p, err := f.prefix()
	if err != nil {
		return nil, err
	}
	tag, err := demoTag(key, p, f.Sequence)
	if err != nil {
		return nil, err
	}
	return append(p, tag...), nil
}

// StreamDataFrame carries a chunk, optionally overriding stream semantics.
type StreamDataFrame struct {
	Control  Control243
	Suite    CryptoSuite
	Epoch    uint64
	StreamID uint64
	Payload  []byte
	Override SemanticPair
	Sequence uint64
}

func (f StreamDataFrame) prefix() ([]byte, error) {
	cb, err := f.Control.Encode()
	if err != nil {
		return nil, err
	}
	out := append([]byte{}, v4Magic...)
	out = append(out, cb, byte(KindStreamData), byte(f.Suite))
	out = append(out, EncodeS243(f.Epoch)...)
	out = append(out, EncodeS243(f.StreamID)...)
	out = append(out, EncodeS243(uint64(len(f.Payload)))...)
	out = append(out, f.Payload...)
	out = append(out, encodeSemanticPair(f.Override)...)
	return out, nil
}

// Serialize builds the wire frame (prefix + AES-256-GCM tag).
func (f StreamDataFrame) Serialize(key []byte) ([]byte, error) {
	p, err := f.prefix()
	if err != nil {
		return nil, err
	}
	tag, err := demoTag(key, p, f.Sequence)
	if err != nil {
		return nil, err
	}
	return append(p, tag...), nil
}

// StreamCloseFrame closes a stream.
type StreamCloseFrame struct {
	Control  Control243
	Suite    CryptoSuite
	Epoch    uint64
	StreamID uint64
	Payload  []byte
	Sequence uint64
}

func (f StreamCloseFrame) prefix() ([]byte, error) {
	cb, err := f.Control.Encode()
	if err != nil {
		return nil, err
	}
	out := append([]byte{}, v4Magic...)
	out = append(out, cb, byte(KindStreamClose), byte(f.Suite))
	out = append(out, EncodeS243(f.Epoch)...)
	out = append(out, EncodeS243(f.StreamID)...)
	out = append(out, EncodeS243(uint64(len(f.Payload)))...)
	out = append(out, f.Payload...)
	return out, nil
}

// Serialize builds the wire frame (prefix + AES-256-GCM tag).
func (f StreamCloseFrame) Serialize(key []byte) ([]byte, error) {
	p, err := f.prefix()
	if err != nil {
		return nil, err
	}
	tag, err := demoTag(key, p, f.Sequence)
	if err != nil {
		return nil, err
	}
	return append(p, tag...), nil
}

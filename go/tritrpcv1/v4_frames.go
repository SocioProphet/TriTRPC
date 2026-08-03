package tritrpcv1

// v4 hot-path frames — Go port, byte-identical to the Python oracle (frames.py). A frame is a
// canonical prefix + a 16-byte AEAD tag. The prefix is MAGIC + control + kind + suite + S243(epoch)
// + frame-specific fields + payload. The tag is AES-256-GCM over the prefix as AAD with empty
// plaintext (the demo AesGcmDemoTagProvider): nonce = "TRPC" || seq(8B big-endian). This is the FIPS
// AES-256-GCM sealing lane the CryptoProfile suite selects — a real tag, not a stub.

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

var v4Magic = []byte{0xf3, 0x2a}

const demoNoncePrefix = "TRPC" // the reference AesGcmDemoTagProvider nonce prefix

type CryptoSuite uint8

const (
	SuiteResearch      CryptoSuite = 0
	SuiteFIPSClassical CryptoSuite = 1
	SuiteCNSA2Ready    CryptoSuite = 2
	SuiteReserved      CryptoSuite = 3
)

type FrameKind uint8

const (
	KindUnaryReq     FrameKind = 0
	KindUnaryRsp     FrameKind = 1
	KindStreamOpen   FrameKind = 2
	KindStreamData   FrameKind = 3
	KindStreamClose  FrameKind = 4
	KindBeaconCap    FrameKind = 5
	KindBeaconIntent FrameKind = 6
	KindBeaconCommit FrameKind = 7
	KindError        FrameKind = 8
)

// demoTag computes the AES-256-GCM tag over `prefix` (AAD, empty plaintext) at `seq`.
func demoTag(key, prefix []byte, seq uint64) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("AES-256-GCM demo tag requires a 32-byte key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 0, 12)
	nonce = append(nonce, demoNoncePrefix...)
	var seqb [8]byte
	binary.BigEndian.PutUint64(seqb[:], seq)
	nonce = append(nonce, seqb[:]...)
	return gcm.Seal(nil, nonce, nil, prefix), nil // empty plaintext -> 16-byte tag
}

// DemoKey returns the reference demo key bytes(range(32)) = 00 01 .. 1f.
func DemoKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

// HotUnaryFrame is the aggressive v4 hot unary frame.
type HotUnaryFrame struct {
	Control     Control243
	Suite       CryptoSuite
	Kind        FrameKind
	Epoch       uint64
	RouteHandle uint8 // direct Handle243 (0..242)
	Payload     []byte
	Sequence    uint64
}

func (f HotUnaryFrame) prefix() ([]byte, error) {
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
	out = append(out, EncodeS243(uint64(len(f.Payload)))...)
	out = append(out, f.Payload...)
	return out, nil
}

// Serialize builds the wire frame (prefix + AES-256-GCM tag).
func (f HotUnaryFrame) Serialize(key []byte) ([]byte, error) {
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

// BeaconFrame is a v4 beacon (capability / intent / commit).
type BeaconFrame struct {
	Control        Control243
	Suite          CryptoSuite
	Kind           FrameKind
	Epoch          uint64
	IdentityHandle uint8 // direct Handle243
	Phase          uint8 // 1..7
	Topic          uint8 // 1..23
	Payload        []byte
	Sequence       uint64
}

func (f BeaconFrame) prefix() ([]byte, error) {
	cb, err := f.Control.Encode()
	if err != nil {
		return nil, err
	}
	h, err := EncodeHandle243(Handle243{Kind: HandleDirect, Direct: f.IdentityHandle})
	if err != nil {
		return nil, err
	}
	braid, err := EncodeBraid243(f.Phase, f.Topic)
	if err != nil {
		return nil, err
	}
	out := append([]byte{}, v4Magic...)
	out = append(out, cb, byte(f.Kind), byte(f.Suite))
	out = append(out, EncodeS243(f.Epoch)...)
	out = append(out, h...)
	out = append(out, braid)
	out = append(out, EncodeS243(uint64(len(f.Payload)))...)
	out = append(out, f.Payload...)
	return out, nil
}

// Serialize builds the wire frame (prefix + AES-256-GCM tag).
func (f BeaconFrame) Serialize(key []byte) ([]byte, error) {
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

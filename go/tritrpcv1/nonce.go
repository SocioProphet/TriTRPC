package tritrpcv1

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// DeriveNonce builds a 12-byte AES-GCM nonce: contextPrefix (exactly 4 bytes) || seq (8B big-endian).
// This is the formalized nonce/session derivation (reference/nonce_derivation.py) that the v4 frame
// AEAD lane uses via demoTag. AES-GCM nonce reuse under a fixed key is catastrophic, so the
// derivation is bounds-checked and paired with NonceLedger for reuse protection.
func DeriveNonce(contextPrefix []byte, seq uint64) ([]byte, error) {
	if len(contextPrefix) != 4 {
		return nil, errors.New("nonce context prefix must be exactly 4 bytes")
	}
	nonce := make([]byte, 0, 12)
	nonce = append(nonce, contextPrefix...)
	var seqb [8]byte
	binary.BigEndian.PutUint64(seqb[:], seq)
	return append(nonce, seqb[:]...), nil
}

// NonceLedger enforces strictly-monotonic, no-reuse nonce issuance per session (context prefix).
type NonceLedger struct {
	last map[string]uint64
	set  bool
}

// NewNonceLedger returns an empty ledger.
func NewNonceLedger() *NonceLedger { return &NonceLedger{last: map[string]uint64{}} }

// Issue returns the nonce for (contextPrefix, seq), refusing a reused or non-increasing sequence
// within a session; the same sequence under a different context prefix is allowed.
func (l *NonceLedger) Issue(contextPrefix []byte, seq uint64) ([]byte, error) {
	nonce, err := DeriveNonce(contextPrefix, seq)
	if err != nil {
		return nil, err
	}
	key := string(contextPrefix)
	if last, ok := l.last[key]; ok && seq <= last {
		return nil, fmt.Errorf("nonce sequence %d <= last %d for this session (reuse/non-monotonic — refused)", seq, last)
	}
	l.last[key] = seq
	return nonce, nil
}

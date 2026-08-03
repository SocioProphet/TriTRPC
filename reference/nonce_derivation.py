"""Nonce / session derivation for beaconed and streamed operation (vNext hot-path gap #5) — fail-closed.

AES-GCM nonce reuse under a fixed key is catastrophic (it leaks the auth key). For beaconed/streamed
operation the nonce MUST be unique per (session, sequence). This normalizes the derivation used by the
frame AEAD lane:

    nonce = context_prefix (4 bytes) || sequence (8 bytes, big-endian)   -> 12 bytes (GCM standard)

and provides a NonceLedger that enforces, fail-closed, that within a session sequences are strictly
monotonic and never reused, and that the sequence fits 8 bytes (no wrap). This is the "context-sequence"
noncePolicy the CryptoProfile approved-mode block declares (FIPS SP 800-38D IV construction).

FIPS: no primitive here (derivation + a reuse guard); the AEAD itself is AES-256-GCM in an approved
suite. Does not change the wire — it pins how the existing 12-byte frame nonce is formed.
"""
from __future__ import annotations

_MAX_SEQ = (1 << 64) - 1


class NonceError(Exception):
    pass


def derive_nonce(context_prefix: bytes, sequence: int) -> bytes:
    """context_prefix (exactly 4 bytes) || sequence (8 bytes big-endian) -> a 12-byte GCM nonce."""
    if len(context_prefix) != 4:
        raise NonceError("context_prefix must be exactly 4 bytes")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0 or sequence > _MAX_SEQ:
        raise NonceError("sequence must be a 0..2^64-1 integer (no wrap)")
    return context_prefix + sequence.to_bytes(8, "big")


class NonceLedger:
    """Tracks the highest sequence issued per session; enforces strict monotonic, no-reuse issuance."""

    def __init__(self) -> None:
        self._last: dict[bytes, int] = {}

    def issue(self, context_prefix: bytes, sequence: int) -> bytes:
        """Issue a nonce for (session=context_prefix, sequence). Refuses reuse or non-increasing sequence."""
        nonce = derive_nonce(context_prefix, sequence)  # validates shape/range first
        last = self._last.get(context_prefix)
        if last is not None and sequence <= last:
            raise NonceError(
                f"sequence {sequence} <= last issued {last} for this session (reuse / non-monotonic — refused)")
        self._last[context_prefix] = sequence
        return nonce

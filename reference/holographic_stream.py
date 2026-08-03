"""Holographic message stream (experimental reference) — each fragment holds a low-res whole.

Split a message into N fragments so that (a) any single fragment already encodes a LOW-RESOLUTION
copy of the WHOLE message, and (b) full-resolution content is not legible until the full stream is
assembled. Spread-spectrum holography:

  1. DELOCALIZE with a unitary transform: y = WHT(x). The Walsh-Hadamard transform is orthogonal and
     integer-exact (WHT(WHT(x)) = n*x), and maximally smears every input byte across every
     coefficient — the whole is encoded in the whole spectrum.
  2. DISTRIBUTE: fragment i owns the strided coefficient set {i, i+N, i+2N, ...}. Because the set is
     spread across the whole spectrum, inverse-transforming ONE fragment alone (zero-filling the rest)
     reconstructs a low-resolution copy of the WHOLE message (a block-averaged blur).
  3. THRESHOLD (illegible-until-full): add integer keyed masks m_i that SUM TO ZERO over the full set.
     Any strict subset leaves a residual mask (noise); only the full set cancels (sum m_i = 0), so the
     coherent reconstruction is exact only at full assembly. Integer masks cancel EXACTLY (no float
     drift), so full assembly recovers the message byte-for-byte and is reproducible cross-platform.

This is a coding/holography scheme, not encryption: the mask key yields the per-fragment low-res
preview; confidentiality is the CryptoProfile AEAD lane's job. For a hard k-of-n threshold (any k ->
exact, fewer -> nothing) use Shamir secret sharing instead (no low-res preview). Stdlib only.
"""
from __future__ import annotations

import hashlib
import random

_MASK_MAG = 1_000_003  # mask magnitude: large vs byte range so any residual is noise


def wht(a: list[int]) -> list[int]:
    """In-place fast Walsh-Hadamard transform (len must be a power of two)."""
    a = a[:]
    n = len(a)
    h = 1
    while h < n:
        for i in range(0, n, h * 2):
            for j in range(i, i + h):
                x, y = a[j], a[j + h]
                a[j], a[j + h] = x + y, x - y
        h *= 2
    return a


def iwht(a: list[int]) -> list[int]:
    """Inverse WHT. For a full-assembly spectrum this is exact integer division by n."""
    n = len(a)
    t = wht(a)
    return [v // n for v in t]


def _pad_len(m: int) -> int:
    L = 1
    while L < max(m, 1):
        L *= 2
    return L


def _mask(key: str, i: int, n: int) -> list[int]:
    rnd = random.Random(hashlib.sha256(f"{key}:{i}".encode()).digest())
    return [rnd.randrange(-_MASK_MAG, _MASK_MAG) for _ in range(n)]


def encode(msg: bytes, n_frags: int, key: str, masked: bool = True) -> dict:
    """Encode msg into n_frags holographic fragments. Returns {fragments, L, orig_len, n_frags, masked}."""
    if n_frags < 2:
        raise ValueError("n_frags must be >= 2")
    L = _pad_len(len(msg))
    x = list(msg) + [0] * (L - len(msg))
    y = wht(x)

    masks = None
    if masked:
        masks = [_mask(key, i, L) for i in range(n_frags - 1)]
        masks.append([-sum(masks[k][t] for k in range(n_frags - 1)) for t in range(L)])  # zero-sum

    fragments = []
    for i in range(n_frags):
        f = [0] * L
        for k in range(i, L, n_frags):  # this fragment's strided slice of the spectrum
            f[k] = y[k]
        if masked:
            f = [f[t] + masks[i][t] for t in range(L)]
        fragments.append(f)
    return {"fragments": fragments, "L": L, "orig_len": len(msg), "n_frags": n_frags, "masked": masked}


def reconstruct(fragments_subset: list[list[int]], L: int, orig_len: int) -> bytes:
    """Coherent sum of a subset of fragments -> bytes. Exact iff the subset is the full set (masks cancel)."""
    y = [0] * L
    for f in fragments_subset:
        for t in range(L):
            y[t] += f[t]
    x = iwht(y)
    return bytes(max(0, min(255, v)) for v in x[:orig_len])


def lowres_preview(enc: dict, index: int, key: str) -> bytes:
    """The low-res whole a single fragment encodes: unmask fragment `index` and inverse-transform it
    alone (zero-filling the rest). Demonstrates the holographic property — one piece, the whole blurred."""
    f = enc["fragments"][index][:]
    if enc["masked"]:
        m = _mask(key, index, enc["L"])
        f = [f[t] - m[t] for t in range(enc["L"])]
    return reconstruct([f], enc["L"], enc["orig_len"])

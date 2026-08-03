# Q3 ECC Profile v0 — the default ternary/qutrit error-correction, for interop

The whitepaper owes "a default Q3 ECC profile so multi-vendor interop is real from day one." Q3 is
the qutrit / ternary rail. Two rails, one checkable profile:

- **classical-ternary** — **Reed-Solomon over GF(3^m)**. Symbols are elements of GF(3^m); a primitive
  RS code has block length `n = 3^m − 1`, `k` message symbols, and corrects `t = ⌊(n−k)/2⌋` symbol
  errors. **Canonical default: RS over GF(9)** (`m=2`, `n=8`, `k=4`, `t=2`) — every vendor implements
  this one day-one.
- **qutrit-quantum** — a ternary `[[n,k,d]]_3` **stabilizer code**; must satisfy the quantum Singleton
  bound `n − k ≥ 2(d−1)`. Example: the qutrit `[[5,1,3]]_3` perfect code.

`tools/verify_q3_ecc_profile.py` checks each declared code is a VALID code (not just well-typed): RS
requires `n = 3^m − 1`, `1 ≤ k < n`, and `t = ⌊(n−k)/2⌋ ≥ 1`; stabilizer requires `0 ≤ k < n`, `d ≥ 1`,
and the quantum Singleton bound. So a multi-vendor profile that claims impossible parameters is
refused. **Additive:** selects the rail's ECC; does NOT change the TritPack243/TLEB3 wire (v1/v4/vNext
unaffected). **FIPS-neutral** (error-correction, not cryptography).

# Mesh SCHEMA-ID & body-CID (reproducible content addresses)

A `WorkUnitPack` carries a `schema_id` and a `body_cid`. For the mesh to work, both must be
**reproducible** — two honest nodes must derive the same values from the same artifacts, or they
could not agree on what they computed. This spec pins how they are derived and ships a recompute
vector.

## SCHEMA-ID = `sha3-256:` of the Avro Parsing Canonical Form

The body's Avro schema (`schemas/avro/work_unit_body.v0.avsc`) is reduced to its **Parsing Canonical
Form** (PCF) per the Avro spec — PRIMITIVES / FULLNAMES / STRIP / ORDER / STRINGS: names become
fullnames, only `name/type/fields/symbols/items/values/size` are kept (doc, aliases, defaults,
logical types stripped), object keys are ordered, and whitespace removed. The SCHEMA-ID is
**SHA3-256** (FIPS 202) of the PCF bytes. Consequence, proven by the verifier: adding `doc`/`default`
noise does **not** change the SCHEMA-ID, but reordering fields or changing an enum symbol **does** —
the id tracks structure, not cosmetics.

## body-CID = `sha256:` of the canonical body

`body_cid` is **SHA-256** (FIPS 180-4) of the body's canonical JSON (sorted keys, no whitespace) — a
dependency-free stand-in for Avro binary; the invariant that matters is that all honest nodes derive
the same CID from the same body, so it is key-order invariant but content sensitive.

`reference/avro_canonical.py` implements PCF + both hashes; `fixtures/mesh/work_unit_schema_id.vector.json`
records `{pcf, schema_id, body, body_cid}` and `tools/verify_avro_schema_id.py` **recomputes** them
(recompute-don't-trust) and proves the invariance/sensitivity properties. Both primitives are
FIPS-approved; this does not touch the tritrpc v4/vNext wire format.

# Avro schema visualization

Status: non-normative documentation tooling

## Purpose

TriTRPC uses Avro on the Path-A payload lane and preserves Avro as an important schema contract surface. A schema diagram is useful for review, onboarding, and protocol discussion, but it must never become the protocol authority. The `.avsc` source, canonical fixture vectors, and implementation tests remain normative.

`tools/render_avro_schema_lom.py` renders an Avro record schema as a Graphviz DOT diagram using a LOM-inspired lane grammar:

1. `Schema`
2. `Category`
3. `Aggregate Element`
4. `Simple Data Element`
5. `Datatype`
6. `Value`

The result is deterministic text output. Reviewers can diff it, regenerate it, and render it through Graphviz when image artifacts are needed.

## Usage

```bash
python tools/render_avro_schema_lom.py \
  --schema path/to/schema.avsc \
  --out docs/diagrams/schema_lom.dot
```

Optional rendering, when Graphviz is installed:

```bash
dot -Tsvg docs/diagrams/schema_lom.dot -o docs/diagrams/schema_lom.svg
dot -Tpng docs/diagrams/schema_lom.dot -o docs/diagrams/schema_lom.png
```

## Boundary

This repository owns the canonical TriTRPC protocol renderer because TriTRPC owns the Avro/Path-A protocol semantics, fixture vectors, and deterministic reference behavior.

Downstream consumers may wrap the renderer:

- `SourceOS-Linux/sourceos-spec` may generalize the pattern into a contract visualization profile.
- `SourceOS-Linux/sourceos-devtools` may expose an operator command such as `sourceosctl schemas diagram`.
- Linux realization repositories should consume generated documentation only; they should not own protocol schema visualization rules.

## DALL-E / generated art policy

Image-generation output can be used as a visual style sketch, but it is not evidence. It must not be treated as a protocol diagram unless every field, type, edge, and label was generated from a checked-in schema or reviewed against one.

For protocol documentation, the accepted source of truth is:

```text
.avsc / fixture manifest / canonical fixture vectors -> deterministic DOT -> optional rendered image
```

not:

```text
prompt -> image model -> plausible diagram
```

## Descriptor manifest reference checks

`tools/check_descriptor_manifest_refs.py` scans descriptor manifests, such as `encoded_payload_manifest*.json`, and reports local schema/sample/binary references that point at missing files.

Strict mode:

```bash
python tools/check_descriptor_manifest_refs.py
```

Warn-only compatibility mode:

```bash
python tools/check_descriptor_manifest_refs.py --warn-only
```

Warn-only mode exists so legacy fixture debt can be exposed in `make verify` without blocking unrelated parity work. Once the existing missing descriptor artifacts are repaired, CI should switch to strict mode.

## Review rule

A committed diagram must satisfy all of the following:

- generated from a checked-in schema;
- reproducible with the committed renderer;
- labeled as non-normative;
- regenerated when the source schema changes;
- excluded from semantic claims unless validated against the schema and fixture vectors.

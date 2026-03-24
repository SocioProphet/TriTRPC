# What is TriTRPC vNext?

TriTRPC vNext is the public design pack for the next generation of TriTRPC.

At a high level it combines five ideas:

1. compact authenticated transport
2. route handles and stream inheritance
3. ternary-native payload and control surfaces
4. braided semantic cadence for phase/topic/state signaling
5. standards-inspired hardening and auditability

## Why this matters

Most transport systems are good at moving bytes.
TriTRPC vNext is trying to be good at moving meaning efficiently.

That means:
- fewer repeated routing bytes
- explicit hot control fields
- semantic coordinates instead of repeated semantic strings
- stream defaults instead of per-frame repetition
- beacons for shared context
- stronger audit and replay surfaces

## The shortest summary

TriTRPC vNext tries to make transport intelligence a first-class protocol feature.

## Where to start

- `docs/vnext/README.md`
- `docs/vnext/PERFORMANCE_AND_TESTING.md`
- `docs/vnext/braided_cadence_impl_v4.md`
- `spec/drafts/tritrpc_vnext_mini_spec.md`
- `reference/experimental/tritrpc_requirements_impl_v4/`

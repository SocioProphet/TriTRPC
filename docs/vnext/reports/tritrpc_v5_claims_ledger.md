# TRiTRPC v5 claims ledger

| Claim | Status | Evidence source | Overclaim risk |
| --- | --- | --- | --- |
| Stable TritRPC v1 exists in the live public repo | Repository fact | README repository status | Low |
| Experimental TriTRPC vNext exists as a public design pack | Repository fact | README and `docs/vnext/README.md` | Low |
| Stable v1 guarantees canonical encoding, parity, strict verification, and traceable theory | Repository fact | README guarantees section | Low |
| Current stable surface uses Path-A Avro, Path-B toy subset, and XChaCha20-Poly1305 authenticated framing | Repository fact | README plus theory/spec | Low |
| Go/Rust ports use explicit per-frame nonces from fixtures | Repository fact | theory/spec | Low |
| SECURITY.md is currently placeholder-grade in the live repo | Repository fact | SECURITY.md | Low |
| CI currently runs one `make verify` workflow on push/PR | Repository fact | README and CI workflow | Low |
| Protobuf serialization is not canonical | External fact | protobuf serialization-not-canonical guidance | Low |
| Deterministic protobuf serialization is still not canonical | External fact | protobuf serialization-not-canonical guidance | Low |
| gRPC is built on HTTP/2 streams and framing | External fact | gRPC HTTP/2 documentation | Low |
| Go FIPS claims are bounded to module version and operating environment | External fact | Go FIPS documentation | Low |
| IBM Statevector supports non-power-of-two subsystem dimensions | External fact | IBM Qiskit Statevector documentation | Low |
| Path-H payloads average 16.4 bytes on the five-event benchmark | Modeled benchmark result | paper benchmark harness | Medium |
| Protocol Buffers payloads average 25.4 bytes on the five-event benchmark | Modeled benchmark result | paper benchmark harness | Medium |
| Thrift compact payloads average 25.6 bytes on the five-event benchmark | Modeled benchmark result | paper benchmark harness | Medium |
| Thrift binary payloads average 61.4 bytes on the five-event benchmark | Modeled benchmark result | paper benchmark harness | Medium |
| Current TriTRPC-style full frames average about 151 bytes on the five-event benchmark | Modeled benchmark result | paper benchmark harness | Medium |
| Path-H-style full frames average about 39.4 bytes on the five-event benchmark | Modeled benchmark result | paper benchmark harness | Medium |
| vNext measured hot unary frame is 52 bytes in the current design pack | Measured design-pack fact | `docs/vnext/PERFORMANCE_AND_TESTING.md` | Low |
| vNext measured stream DATA frame is 35 bytes in the current design pack | Measured design-pack fact | `docs/vnext/PERFORMANCE_AND_TESTING.md` | Low |
| vNext braid coordinate is 1 byte in the current design pack | Measured design-pack fact | `docs/vnext/PERFORMANCE_AND_TESTING.md` | Low |
| vNext large opaque payload advantage mostly disappears | Measured design-pack fact | `docs/vnext/PERFORMANCE_AND_TESTING.md` | Low |
| Inherited defaults beat per-frame semantic carriage after 2 data frames | Measured design-pack fact | performance note plus cadence docs | Low |
| A separate beacon beats per-frame semantic carriage after 13 data frames | Measured design-pack fact | performance note plus cadence docs | Low |
| TriTRPC is structurally advantaged on authenticated hot-path control transport | Future theorem / proposal | vNext docs plus paper argument | Medium |
| Braided beaconing is an independently developed privacy-shaping design | Future theorem / authorship framing | project authorship decision | Medium |
| Path-H is the classical sidecar around future qutrit-aware systems | Future extension | paper hybrid design | Medium |

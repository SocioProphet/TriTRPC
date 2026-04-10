# Notes on staged content

This GitHub-staged subtree intentionally includes the core review surface:
- security docs,
- schemas and CDDL,
- reference verifier implementation,
- compact internal codec helpers.

Two classes of artifacts were not staged directly through the connector in this pass:
1. signed example vectors containing token-shaped values, because connector safety checks treated those serialized examples as sensitive;
2. the local test/workflow bundle, because it depends on the full fixture set from the sandbox pack.

The complete sandbox pack remains the source of truth for those omitted items and can be copied in a follow-up branch if we want the full executable fixture/workflow layer upstream as well.

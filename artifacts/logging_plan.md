# Logging Plan

- All non-research deployments emit hash-chained audit records.
- Frame emission, validation failures, suite negotiation, and configuration changes are logged.
- Logs preserve canonical wire identity, suite, frame kind, and decision outcome.
- Audit records are forwarded to incident response and retained outside the node boundary.

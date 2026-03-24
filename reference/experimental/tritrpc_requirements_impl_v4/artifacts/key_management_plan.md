# Key Management Plan

- Separate transport/session keys from application identifiers and handles.
- Keep nonce/IV construction inside the selected cryptographic boundary when possible.
- Distinguish key-establishment keys, signature keys, and AEAD traffic keys.
- Rotate operational keys under a documented policy and after suspected compromise.
- Record key provenance, activation time, deactivation time, and destruction events in audit logs.

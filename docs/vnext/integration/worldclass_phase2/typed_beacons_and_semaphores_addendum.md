# TriTRPC vNext Addendum — Typed Beacons and Semaphores

This addendum upgrades the current vNext design pack from opaque semantic bundle carriage to typed semantic bundle refs and semaphore-aware coordination.

## Why this addendum exists

The current design already has:
- `Control243`
- `S243`
- `Handle243`
- `Braid243`
- `State243`
- stream inheritance
- capability / intent / commit beacons

What is still missing is protocol-native typing for:
- semantic bundle refs
- environment epoch bundles
- temporal constraint refs
- semaphore lifecycle control

## Typed beacon payload rules

### BEACON_CAP
Carries:
- environment epoch bundle ref
- capability handles
- codebook versions
- alias map refs
- policy epoch refs

### BEACON_INTENT
Carries:
- beacon context bundle ref
- optional delta ref
- inherited stream defaults
- review / novelty / pressure posture

### BEACON_COMMIT
Carries:
- artifact commit bundle ref
- promotion or tombstone action
- replay requirement bit

### BEACON_LOAD
Carries:
- queue pressure band
- stream contention band
- shed posture
- service-time band

### BEACON_SEMAPHORE
Carries:
- semaphore id
- request / grant / revoke / release action
- permit class
- fairness policy
- expiration and witness refs

## Semaphore control law

- Observe under shared permits.
- Promote, mutate, or commit under exclusive permits.
- Freeze under explicit barrier or quorum if policy requires it.
- Revoke only with policy basis and replay-safe logging.

## Compatibility note

The hot frame remains compact because beacon payloads carry refs/handles rather than full semantic bundles.

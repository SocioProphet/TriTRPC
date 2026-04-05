# DescriptorService contract v0.1

## Goal

Provide a minimal typed transport surface for descriptor registration and lookup.

## Methods

- `RegisterGeneralDescriptor`
- `GetGeneralDescriptor`
- `UpdateGeneralDescriptor`

## Request and response outline

### RegisterGeneralDescriptorRequest
- `descriptor`: `GeneralDescriptor`
- `contextId`: `string`
- `schemaId`: `string`

### RegisterGeneralDescriptorResponse
- `descriptorId`: `string`
- `status`: `string`

### GetGeneralDescriptorRequest
- `descriptorId`: `string`

### GetGeneralDescriptorResponse
- `descriptor`: `GeneralDescriptor`

### UpdateGeneralDescriptorRequest
- `descriptorId`: `string`
- `descriptor`: `GeneralDescriptor`

### UpdateGeneralDescriptorResponse
- `descriptorId`: `string`
- `status`: `string`

## Contract rule

The wire contract MUST remain typed, deterministic, and replayable.
Agentic inference may exist inside implementations, but the on-wire contract must not collapse into untyped prompt payloads.

# OrderService contract v0.1

## Goal

Provide a minimal typed transport surface for governed work requests.

## Methods

- `CreateOrder`
- `ValidateOrder`
- `GetOrderStatus`

## Request and response outline

### CreateOrderRequest
- `order`: `OrderDescriptor`
- `contextId`: `string`
- `schemaId`: `string`

### CreateOrderResponse
- `orderId`: `string`
- `status`: `string`

### ValidateOrderRequest
- `orderId`: `string`

### ValidateOrderResponse
- `orderId`: `string`
- `validationPassed`: `boolean`
- `completedChecks`: `string[]`
- `failedChecks`: `string[]`
- `evidenceRefs`: `string[]`

### GetOrderStatusRequest
- `orderId`: `string`

### GetOrderStatusResponse
- `orderId`: `string`
- `state`: `string`
- `evidenceRefs`: `string[]`

## Contract rule

The order surface should stay narrow and deterministic. Implementations may call richer policy or agent subsystems internally, but the exposed wire contract must remain inspectable and replayable.

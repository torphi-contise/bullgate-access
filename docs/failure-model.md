# Failure model

Bullgate Access separates transport failures, semantic rejections, concurrency
conflicts, and operational failures. Integrations must preserve that distinction.
Human-readable messages are diagnostic text; machines branch on stable error codes
and current HTTP status.

## Failure classes

### Authentication failure

An absent, malformed, expired, revoked, cryptographically invalid, inactive-scope,
or internally inconsistent integration credential is rejected as unauthenticated.
The response does not identify which validation failed. The caller must replace or
repair its server credential; retrying the same value is not recovery.

The HTTP challenge contains only the Bearer scheme. It does not reveal whether the
credential id, secret, lifetime, revocation, topology, permission vocabulary, or token
shape failed. A valid credential without the required route permission is a separate
authorization failure and produces HTTP 403 rather than HTTP 401.

An inactive or malformed identity session similarly becomes `session-inactive`.
Access unavailability is not equivalent to an inactive session: a consumer must not
log a person out merely because introspection could not be completed.

### Authorization failure

The authenticated integration client must have the permission attached to the route.
Scope always comes from that credential. Supplying a different realm, environment,
or identity reference does not elevate access.

### Input rejection

Missing fields, invalid email/phone syntax, unsupported protocol versions, invalid
application-client keys, and short passwords are caller-correctable. Do not retry
unchanged input.

For bootstrap, strict JSON/manifest, topology, policy, provider, and client-metadata
violations are rejected before the database transaction begins. This guarantees no
change from that invocation, but it does not prove that a different concurrent or
earlier process made no change.

### Policy or state conflict

Examples include a disabled authenticator, registration-purpose session on a product
mutation, duplicate email, an already linked provider, unlinking the last
authenticator, and an unavailable AccessFlow action. The request may become valid
only after configuration or server state changes.

### Concurrency conflict

`revision-conflict` means another transition changed relevant state after the caller's
snapshot. Read the latest snapshot, render its advertised actions, and make a new
decision. Never blindly repeat the stale action with a new revision.

`request-id-conflict` means the same request id was presented with different canonical
input. Generate a new id for a genuinely new operation; preserve the original id only
for an exact retry.

### Delivery or dependency failure

Email/SMS failures are operational failures after or around a durable reservation.
Retry behavior depends on the stored request state and cooldown. Never issue a new
side effect merely because the first HTTP response was lost; first replay the exact
request or refresh the flow.

Provider adapters do not share one universal error shape:

| Boundary | Implemented failure surface | Important distinction |
| --- | --- | --- |
| SMTP password recovery | Missing configuration or caught construction/transport failure returns `false`; caller cancellation propagates. | `false` does not prove that no durable reset token exists or that a provider performed no effect. |
| Twilio Verify transport | Non-success throws with HTTP status and a parseable structured error code; arbitrary response body is not copied. | A timeout or rejection is not proof that no message was delivered. |
| Google ID token | Signed-token rejection returns no assertion. | Missing trusted configuration is not an identity rejection. |
| Google access token | Provider error, network failure, malformed JSON, invalid audience/authorized party, or missing required claims returns no assertion. | UserInfo failure affects only optional display name after identity claims are accepted. |
| Apple identity token | Non-cancellation discovery or validation failure returns no assertion. | Null does not identify whether signing, issuer, lifetime, audience, claims, or provider availability failed. |

`IsAvailableAsync` on delivery adapters reports environment configuration presence, not
live provider health. A true result cannot justify skipping normal reserve, perform,
finalize/fail handling or predict that the external request will succeed.

### Bootstrap and protected-configuration failure

Bootstrap resolves every declared resource under one transaction-scoped advisory lock.
A compatibility mismatch, persistence exception, cancellation, or failure before
commit rolls back that run. Existing resources are not silently renamed, moved,
reactivated, or granted different integration permissions. A failed run returns no
trustworthy newly issued clear credential; inspect the committed database state before
attempting operational recovery.

Protected configuration has fail-closed read behavior. Missing or inactive
environments return absence, but an unsupported envelope version, invalid envelope
shape, AES-GCM authentication failure, or strict JSON failure throws a configuration
error. Callers must not reinterpret such an error as “provider not configured,” fetch
secrets from another environment, or accept request-supplied configuration.

The same authentication failure covers a wrong installation key, a moved envelope,
changed associated data, and tampered encrypted fields. That collapse avoids exposing
which cryptographic check failed; diagnosis uses deployment and database evidence, not
partial plaintext. Restoring only the database without its matching external master
key does not restore usable protected configuration.

## Anti-enumeration behavior

Authentication and recovery intentionally collapse facts that would reveal account
existence:

- password login returns the same credential error for malformed/unknown email and a
  wrong password;
- phone recovery returns accepted timing even when no identity owns the phone or a
  rate/cooldown reservation is not granted;
- the public email-recovery endpoint must not expose its internal `IdentityNotFound`
  distinction;
- phone confirmation collapses wrong, expired, exhausted, consumed, and otherwise
  non-ready challenges to `invalid-code`.

This collapse is deliberately bounded. Malformed input, an invalid public
application-client key, and disabled recovery policy are rejected before ordinary
ownership-sensitive reservation. Provider preflight, delivery, cancellation, and
activation failures also remain explicit operational errors under the current contract.
An integration must not describe every phone-recovery failure as a successful accepted
request or claim that every provider failure occurs before candidate resolution.

Internal services retain some distinctions for orchestration and observability. An
HTTP adapter must not accidentally publish them.

Google and Apple validation expose a single `invalid-token` application outcome when
the provider assertion is rejected or required identity claims are absent. That result
does not tell a consumer which signature, issuer, audience, lifetime, subject, e-mail,
or provider interaction check failed. Provider unavailability must not be described as
proof that a person's identity is invalid.

## Deletion outcomes and ambiguity

Account deletion collapses missing, malformed, unknown, expired, revoked,
registration-purpose, wrong-environment, and wrong-realm session bearers to HTTP 401
`session-inactive`. The collapse protects session and identity state; it also means the
response is not evidence that an identity currently exists or that a previous attempt
did not commit.

HTTP 204 confirms only the local Access database transaction. That transaction first
removes every complete flow graph found through `AccessFlowDataSubject`, then removes
the identity and its dependent records. An exception or cancellation before commit is
not success. Provider availability is irrelevant because the path performs no provider
operation.

Successful deletion removes the authorizing session, so an exact HTTP retry with the
same bearer returns `session-inactive`. If the original response was lost, that retry is
ambiguous rather than a durable deletion receipt. The consumer owns durable intent,
ordering, idempotency, retries, and repair for its separate database. See
[`identity-erasure.md`](identity-erasure.md).

## Retry matrix

| Signal | Caller behavior |
| --- | --- |
| Invalid input | Correct input; do not retry unchanged. |
| Unauthenticated integration credential | Repair or rotate the server credential. |
| Bootstrap compatibility mismatch | Correct the manifest or perform a separate explicit lifecycle change; do not delete or mutate the existing resource implicitly. |
| Protected-configuration authentication failure | Stop serving configuration-dependent behavior; verify the installation key and stored envelope provenance. Do not fall back to another tenant or request input. |
| `session-inactive` | End or re-establish the identity session only when Access actually returned this result. |
| `revision-conflict` | Fetch the current flow snapshot and reconsider available actions. |
| `request-id-conflict` | Investigate id reuse; use a new id only for a new semantic request. |
| Delivery unavailable | Replay the same request when safe, then obey returned cooldown/state. |
| Lost account-deletion response | Treat the Access outcome as unknown; a later `session-inactive` cannot prove whether the earlier local transaction committed. Follow the consumer's own durable deletion policy. |
| `429 Too Many Requests` | Honor `Retry-After`; do not fan out retries. |
| `5xx` or network failure | Treat outcome as unknown; use idempotency/replay before causing another side effect. |

## Logging rules

Logs may contain resource ids, request ids, flow ids, semantic error codes, provider
operation ids, and elapsed time when operationally necessary. They must not contain:

- integration credential tokens or their secret portion;
- identity session tokens or flow capabilities;
- password-reset tokens, passwords, or verification codes;
- provider client secrets;
- raw protected environment configuration;
- full request bodies containing personal data.

Redaction is part of the security contract, not an optional production setting.

## Source of truth

Exact route/status mapping is defined by endpoint code and generated OpenAPI from the
same revision. Application result enums are internal semantic contracts and need not
map one-to-one to public responses. See also [`http-api.md`](http-api.md),
[`security-model.md`](security-model.md), and
[`concurrency-and-idempotency.md`](concurrency-and-idempotency.md). Account deletion has
its complete graph and retry contract in [`identity-erasure.md`](identity-erasure.md).

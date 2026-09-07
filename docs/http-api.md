# HTTP API

## Authentication model

Application routes authenticate a server-to-server integration credential as a
bearer token. Authentication resolves the workspace, app, environment, realm,
integration client, and its permissions. Requests do not choose a realm.

The API accepts exactly one `Authorization: Bearer <credential>` value. Missing,
malformed, expired, revoked, cryptographically invalid, or inactive-scope credentials
receive the same minimal Bearer challenge with HTTP 401. A valid credential that lacks
the route's exact permission is authenticated but forbidden with HTTP 403.

The resulting principal contains only topology ids and permissions loaded from the
authenticated credential. Request paths and bodies cannot inject or replace those
claims.

The API returns structured, stable error codes. Consumers should branch on the
code, not human-readable text. Responses containing session or flow state must
not be cached by an intermediary.

## Permission map

| Permission | Purpose |
| --- | --- |
| `access:flows:execute` | Registration, login, social authentication, recovery, public client configuration, and `AccessFlow`. |
| `access:sessions:introspect` | Introspect an opaque session token. |
| `access:sessions:revoke-current` | Revoke the presented session. |
| `access:identities:manage-current` | Change the current identity's credentials or contacts and delete it. |
| `access:identities:read` | Read an identity's email or phone inside the authenticated realm. |

Additional permission constants exist for future administrative operations,
but the current API does not expose a Bullgate administrative surface.

## Routes

| Method and path | Permission | Purpose |
| --- | --- | --- |
| `POST /v1/auth/register` | `access:flows:execute` | Register with email and password. |
| `POST /v1/auth/login` | `access:flows:execute` | Authenticate with email and password. |
| `POST /v1/auth/google` | `access:flows:execute` | Authenticate using a server-validated Google token. |
| `POST /v1/auth/apple` | `access:flows:execute` | Authenticate using a server-validated Apple token. |
| `POST /v1/auth/session/introspect` | `access:sessions:introspect` | Return active session and identity state. |
| `POST /v1/auth/session/revoke` | `access:sessions:revoke-current` | Revoke the presented session. |
| `POST /v1/account/password` | `access:identities:manage-current` | Replace the current password. |
| `PUT /v1/account/email` | `access:identities:manage-current` | Replace the current normalized email. |
| `DELETE /v1/account` | `access:identities:manage-current` | Hard-delete the current identity and attributable Access data. |
| `POST /v1/account/social/{provider}/link` | `access:identities:manage-current` | Link Google or Apple. |
| `POST /v1/account/social/{provider}/unlink` | `access:identities:manage-current` | Unlink Google or Apple. |
| `POST /v1/auth/password/recovery/email` | `access:flows:execute` | Request anti-enumerable email recovery. |
| `POST /v1/auth/password/recovery/reset` | `access:flows:execute` | Consume a reset token and replace the password. |
| `POST /v1/auth/password/recovery/phone` | `access:flows:execute` | Start phone recovery. |
| `POST /v1/auth/password/recovery/phone/confirm` | `access:flows:execute` | Confirm the phone OTP and issue reset capability. |
| `GET /v1/config/application-clients/{key}` | `access:flows:execute` | Return public environment and client configuration. |
| `GET /v1/identities/{identityId}/email` | `access:identities:read` | Read email within the credential's realm. |
| `GET /v1/identities/{identityId}/phone` | `access:identities:read` | Read phone and verification time within the credential's realm. |
| `POST /v1/access/flows` | `access:flows:execute` | Start or resume a flow. |
| `GET /v1/access/flows/{flowId}` | `access:flows:execute` | Read the authorized flow snapshot. |
| `POST /v1/access/flows/{flowId}/actions` | `access:flows:execute` | Execute an action from the current revision. |
| `GET /health/live` | none | Report process liveness, not dependency readiness. |

`{provider}` in the table represents the concrete `google` and `apple` routes;
it is not a free-form route parameter.

## Session semantics

Emission responses contain identity state, an opaque token, expiration,
purpose, and whether the identity is new. Introspection includes `active` and
`sessionId`. A registration-purpose session is valid for the registration
journey but must not authenticate product endpoints.

`active: true` means the scoped session belongs to an active identity, is unrevoked,
and has not reached its exclusive `expiresAt` boundary. It does not erase the purpose
distinction: the BFF must still reject registration purpose when resolving a product
principal.

Introspection always returns HTTP 200 for a syntactically accepted request. An unknown,
expired, or revoked session is represented by `active: false` with absent identity
fields. Revocation is idempotent and returns HTTP 204 without revealing whether the
presented token matched a session. A matching row that has expired but has never been
explicitly revoked may still receive its first revocation timestamp.

These uniform session-token outcomes apply only after the integration credential is
authenticated and authorized for the endpoint. A missing or invalid integration
credential still receives HTTP 401, and an authenticated client without the required
session permission still receives HTTP 403.

## Account deletion semantics

`DELETE /v1/account` accepts a body containing `sessionToken`; it accepts no identity
UUID. The integration credential must have `access:identities:manage-current` and fixes
the realm and app environment. Inside that scope, only an active, unrevoked,
unexpired, product-purpose session can select the current identity for deletion.

HTTP 204 means the local Access transaction deleted the identity, its dependent access
material, and every complete flow graph historically attributable through
`AccessFlowDataSubject`. It does not mean that a consumer profile or provider-owned
data was deleted. SMTP, SMS, Google, and Apple are not contacted.

Successful deletion removes the authorizing session. Repeating the request with the
same bearer therefore returns HTTP 401 `session-inactive`; this is not an idempotent
success receipt and does not by itself prove what happened to an earlier request whose
response was lost. See [`identity-erasure.md`](identity-erasure.md) for the complete
authority, reachability, transaction, and integration contract.

## Identity contact reads

Identity e-mail and phone routes accept a caller-controlled identity UUID but always
evaluate it inside the realm fixed by the integration credential. An absent identity,
inactive identity, cross-realm selector, or missing requested identifier returns the
same HTTP 404 `identity-not-found` shape. A stored phone without possession proof is not
absence: it returns HTTP 200 with its canonical value and `verifiedAt: null`.

## Transport secrecy

The Access HTTP surface is designed for a consumer BFF. Response fields have different
exposure rules:

- `sessionToken` is bearer authority and must remain in protected BFF state or an
  appropriate HttpOnly cookie;
- `flowCapability` authorizes one flow and must remain in path-scoped BFF state;
- a phone-confirmation reset `token` is single-use recovery authority and must remain
  in the intended recovery channel;
- provider ID/access tokens and clear passwords are request secrets and must not be
  logged or retained beyond their operation;
- `snapshot`, stable error codes, and explicitly public application-client
  configuration are safe to translate into application-facing semantics after the BFF
  removes server-only bearer material.

DTO names or JSON placement do not downgrade a secret. The integration layer owns the
projection from the Access response to the smaller application response.

## AccessFlow protocol

Protocol version 1 implements `continueRegistration` and `managePhone`.
Snapshots contain `flowId`, `revision`, intent, status, expiry, current step,
available actions, feedback, and an optional terminal result.

The caller supplies a unique `requestId`. An action also supplies
`expectedRevision` and an action id/type returned by the snapshot. A flow
capability authorizes access to that flow and must remain server-side in a BFF
integration.

Exact request and response schemas must be taken from OpenAPI generated by the
same source revision.

## Scoped identity reads

The e-mail and phone routes accept an identity UUID for selection, not authorization.
The integration credential supplies the realm, and persistence joins both identity id
and realm before returning an active identity's contact data. A UUID from another
realm therefore behaves as absent; the request cannot select or override its realm.

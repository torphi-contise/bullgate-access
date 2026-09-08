# Access administrative backend

Implemented under the explicitly approved Admin Iteration 008 proposal (ADMIN-057).
This is the Access backend, not an available Bullgate Admin module or browser UI.
The real Admin caller, current-profile evaluation, catalog registration and explicit
human grants remain Iteration 009. No operator receives permissions automatically.

## Caller and permission boundary

The new `/admin/v1` routes require a dedicated `BullgateAdmin` service credential.
The existing consumer Bearer scheme, its eight-key credential allowlist and its
endpoint policies are unchanged. An Admin service credential cannot substitute for
a consumer integration credential, and a consumer cannot call administrative routes.

Access owns the five exact function keys in `AccessPermission.Administrative`:

| Function | Key |
| --- | --- |
| Directory | `access:identities:list` |
| Identity detail | `access:identities:read` |
| Revoke all current sessions | `access:sessions:revoke-all` |
| Erase Access account | `access:identities:delete` |
| Configuration targets/revisions and complete replacement | `access:configuration:manage` |

Read and revoke-all reuse existing vocabulary. The other three are Admin-only
additions and are not accepted as consumer credential grants. Policies have distinct
caller-specific names even when their Access function key is the same. No wildcard,
role-name bypass, operator-per-app restriction or one-workspace binding is introduced.

## Service authentication and trusted attribution

Access installation configuration accepts `Bullgate__Admin__CredentialSha256`: the
64-character hexadecimal SHA-256 digest of a separately generated **32-random-byte**
Admin service secret. The raw bytes, encoded as canonical unpadded base64url, belong
only in the Admin server's external secret storage. They are not the installation
master key, a consumer credential, an end-user token or a browser cookie.

Send exactly one header:

```text
Authorization: BullgateAdmin <canonical-base64url-32-byte-secret>
```

Access compares the verification hash in constant time. Missing or malformed hash
configuration disables administrative authentication without a fallback or startup
requirement for existing consumer routes. The handler requires HTTPS unless the
actual remote IP is loopback; a caller-supplied Host name does not grant an exception.
TLS termination must supply a correctly established HTTPS request to this handler;
this slice does not configure forwarding trust, certificates or a deployment.

Operational routes also require one `X-Bullgate-Admin-Context` header containing
canonical unpadded base64url of this case-sensitive JSON object:

```json
{
  "operatorId": "opaque-operator-id",
  "sessionId": "opaque-admin-session-id",
  "scopeId": "opaque-admin-scope-id",
  "permission": "access:identities:read"
}
```

All four fields are required, nonempty, at most 128 characters, and contain no
whitespace/control characters. Unknown/duplicate JSON members are rejected. The
permission must exactly match the requested function. Resource ids in routes select
Access targets, not human authority. Scope is opaque attribution, not an Access
workspace id. The fixed service caller id in this contract is `bullgate-admin`.

The authenticated Admin server is the attester: in 009 it must reload its current
session/profile, verify portal access plus the exact function, then construct this
header on every request. Browser values cannot provide this trusted context. Access
does not duplicate the human profile database, call back into Admin, issue request
grants or claim to cancel transactions already dispatched before profile revocation.

## HTTP contract version 1

| Method and path under `/admin/v1` | Required key | Result |
| --- | --- | --- |
| `GET /capabilities` | Service authentication only | `contractVersion: 1` and the five `permissions`; no human/user/configuration data. |
| `GET /realms/{realmId}/identities` | `access:identities:list` | `{ items, nextCursor }`. |
| `GET /realms/{realmId}/identities/{identityId}` | `access:identities:read` | One identity detail. |
| `POST /realms/{realmId}/identities/{identityId}/sessions/revoke` | `access:sessions:revoke-all` | Committed operation receipt, including revoked session count. No body. |
| `DELETE /realms/{realmId}/identities/{identityId}` | `access:identities:delete` | Committed operation receipt, not a consumer/provider deletion claim. No body. |
| `GET /environments` | `access:configuration:manage` | Bounded active configuration targets with current revisions, never decrypted documents. |
| `PUT /environments/{environmentId}/configuration` | `access:configuration:manage` | Committed receipt and new `ETag`. |

Lists accept `pageSize` (default 25, inclusive range 1–50) and `cursor`. Identity
lists additionally accept `identityId`, `email` and `phone`; supplied filters are
combined with AND and compared exactly against current stored normalized values.
No fuzzy matching, normalization guess, export or total-count query is performed.
An absent realm returns 404, distinct from an existing realm with an empty page.

Queries run in PostgreSQL with stable id ordering and at most page size plus one
rows. Continuation cursors bind the exact resource, filters and page size; changing
them requires starting a new query. A cursor is not authority and provides no frozen
snapshot guarantee. There are no per-row HTTP lookups or unbounded directory loads.

Identity detail has `id`, `realmId`, `lifecycle`, `createdAt`, `email` and `phone`.
The contacts are null or `{ value, verified }`. No password, token, CPF/birth-date
view, social subject, proof history or consumer profile is projected. Configuration
targets have `id`, `realmId`, `appId`, `appName`, `key`, `name` and `revision`.

## Mutation receipt and replay

All mutations require exactly one `X-Bullgate-Operation-Id` containing a nonempty
UUID in `D` format. Success returns HTTP 200 and:

```text
operationId, permission, targetId, committedAt, revokedSessions?, revision?
```

The operation and its `admin_operations` receipt commit in one Access transaction.
A transaction-scoped advisory lock serializes each `(callerId, operationId)` before
receipt/target lookup. The table retains caller, original operator/session/scope,
function, target ids, UTC time, purpose-keyed input fingerprint and secret-free
result JSON. It has no foreign key to the erased identity and contains no current
contacts, configuration document, provider secret or token.

An explicit retry with the same caller, operator, scope, function, operation id,
target and typed input returns the stored result without re-executing. A freshly
authenticated Admin session may retry; the original session remains in attribution.
Reusing the id for another input, operator, scope, action or target returns 409.
Replay is checked before target existence and revision, so erasure and a lost
configuration response can replay after their original state is gone. Authentication,
exact permission and structural input validation still apply on each request.

The request fingerprint uses HMAC-SHA-256 with Access's existing installation key
deriver and the separate purpose `admin-operation-input-v1`. It is not an unkeyed
hash of potentially low-entropy provider secrets. No automatic HTTP mutation retry
or mutation-recovery workflow is added. A transport failure is an unknown outcome,
not proof that the operation did not commit.

## Session cut and erasure

Revocation locks the selected identity, then ends its unrevoked, unexpired sessions
across all environments/devices, including registration and product sessions. It
does not change credentials, block the account or prevent subsequent login. Existing
consumer introspection rejects a revoked bearer on the next authenticated request.

The PostgreSQL identity lock serializes with session insertion's foreign-key lock:
issuance committed before the cut is included; a fresh login serialized after it
remains allowed. Existing flow writers lock identities and revalidate the source
session before issuing a successor, so a cut cannot be bypassed by advancing the
revoked registration flow. Already dispatched operations are not retroactively
cancelled and provider effects are not recalled.

Administrative deletion uses `IdentityErasure.DeleteGraphAsync`, the same effect
now shared with consumer deletion below its existing active-product-session gate.
The Admin entry selects its target directly after Admin authorization; it never
fabricates an end-user session. Whole attributable flow graphs are removed first,
then identity-owned access material is cascaded. Unrelated identities and topology
remain. The independent Admin receipt survives. See [identity erasure](identity-erasure.md)
for the graph and the unchanged consumer retry behavior.

## Complete configuration replacement

The body is exactly the existing `AppEnvironmentConfiguration` document, not a
bootstrap/workspace manifest or a partial patch. Supply all eight top-level sections:
`accessPolicy`, `verificationPolicy`, `recoveryPolicy`, `providers`,
`developmentBypass`, `publicConfiguration`, `integrationClients`, `applicationClients`.
Use strict camel-case JSON property names and the current configuration string-enum
representation. Unknown/duplicate members, missing required constructor values,
null sections/clients and invalid domain relationships return a secret-free 400.
Optional schema values, including disabled/omitted optional policy, retain their
existing meaning. Shared `AppEnvironmentConfigurationValidator` performs the same
complete-document validation used by bootstrap without contacting providers.

Send the selected target's exact strong quoted `revision` as `If-Match`; wildcard,
weak, missing or malformed values are not accepted. The opaque revision fingerprints
the environment-bound **encrypted envelope**, not public version, plaintext secret
hash or encryption format alone. Comparison and replacement use the same fixed
PostgreSQL advisory lock (`1101700001`) as CLI bootstrap; a stale value returns 412.

The target and its topology ancestors must already exist and be active. Declared
integration clients must already exist, be active and retain their exact name and
permission set. Declared application clients must already exist and be active;
their compatible public build metadata can change. No resource, credential or grant
is created, moved, reactivated or implicitly erased. Omitted clients remain in
topology/credential storage, while the complete protected declaration/public
projection is replaced as supplied.

Accepted typed policy, recovery URL, client metadata and protected document are
written atomically with the receipt. No encrypted-blob-only update is allowed. The
operation returns no stored provider secret; there is no masked-placeholder language,
rotation UI or per-field editor. A later explicit CLI reapply still replaces the
configuration and changes the revision. No writer handover, import system, CLI
prohibition or automatic rollback is introduced.

## Failures and delivery boundary

| HTTP | Meaning |
| --- | --- |
| 401 | Invalid/missing service authority or required context. |
| 403 | Authenticated context lacks the exact function. |
| 404 | Absent or mismatched target. |
| 400 | Invalid input, JSON, revision syntax or incompatible declaration. |
| 409 | Conflicting operation-id reuse. |
| 412 | Stale configuration envelope revision. |

Application failures return a stable `code`, never submitted secrets. A successful
receipt confirms only the local Access transaction. It does not prove provider
availability, consumer/BAYBO/Billing erasure, real Admin profile evaluation, browser
acceptance, deployment or production readiness. Block/unblock, password reset,
social unlinking, user creation, per-device controls and topology CRUD are not added.

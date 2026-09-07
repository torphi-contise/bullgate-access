# Identity erasure

This document defines the implemented hard-deletion boundary for Bullgate Access.
It explains what authorizes deletion, how `AccessFlowDataSubject` makes historical
personal data reachable, which records are removed, and which responsibilities remain
with an integrating product.

Use this document when implementing `DELETE /v1/account`, reviewing a new identity or
flow relationship, answering an erasure question, or building retrieval material for
an assistant. The executable source and database mappings remain authoritative.

## Contract in one paragraph

An authenticated integration client with `access:identities:manage-current` submits an
opaque product-session bearer. The bearer selects the identity; the integration
credential fixes the only acceptable realm and app environment. Inside one Access
database transaction, the store locks and revalidates that session and active identity,
deletes every complete `AccessFlow` graph linked to the identity through
`AccessFlowDataSubject`, deletes the identity, and lets database cascades remove its
directly owned access material. HTTP 204 confirms only that local Access transaction.
It does not delete a consumer profile or contact an e-mail, SMS, social, or other
external provider.

## Terminology

| Term | Meaning here |
| --- | --- |
| Current identity | The active identity selected by the presented product-session bearer in the authenticated integration scope. |
| Hard deletion | Physical removal of attributable Access records from the Access database. |
| Abandonment | A retained `Abandoned` lifecycle row for a provisional registration identity; it is not hard deletion. |
| Data subject link | Append-only `AccessFlowDataSubject` reachability from a flow to an identity whose personal data that flow retains. |
| Consumer data | Product-owned profile, business, subscription, purchase, media, or other records outside the Access database. |
| Provider data | State held by SMTP, SMS, Google, Apple, or another external system. |

## Ownership boundary

Hard deletion is intentionally local to Bullgate Access.

| Owner | Examples | Effect of `DELETE /v1/account` |
| --- | --- | --- |
| Bullgate Access | Identity, identifiers, authenticators, sessions, registration state, reset material, and attributable flow history. | Removed in the local Access transaction. |
| Integrating product | Product profile and business data associated with an Access identity. | Not changed. The product chooses its own deletion order, retry, idempotency, and support policy. |
| External provider | Mailbox delivery state, SMS records, Google account, Apple account, or other provider-owned state. | Not contacted or revoked by this endpoint. |
| Access topology | Workspace, realm, app, environment, clients, integration credentials, and protected policy. | Retained; these configure the installation rather than belong to the deleted identity. |

Access and a consumer database do not share a distributed transaction. A product may
need to delete both sets of data, but the product owns that cross-system workflow. The
shared Access service does not impose one universal order, queue, scheduler, outbox,
compensation, or support policy on every consumer.

## Authorization: selector is not authority

The request body contains a session token, not an identity UUID. The operation requires
all of the following:

1. The server-to-server integration credential authenticates successfully.
2. That credential has `access:identities:manage-current`.
3. Its claims fix a valid realm and app environment.
4. The presented clear bearer has the expected format and can be hashed.
5. The hash selects a session in that exact app environment.
6. The selected session belongs to an identity in the credential's exact realm.
7. The identity is `Active`.
8. The session purpose is `Product`, not `Registration`.
9. The session has not been revoked.
10. `ExpiresAt` is strictly later than the transaction's current UTC time.

The route and body deliberately accept no caller-selected identity id. An integration
credential proves server scope; a product session proves which current person may act.
Neither one is sufficient alone.

Missing, malformed, unknown, expired, revoked, registration-purpose, wrong-environment,
and wrong-realm bearers are collapsed to HTTP 401 with `session-inactive` for this
operation. This avoids turning the endpoint into a session or identity-state oracle.
Failure leaves the identity graph unchanged.

## Why authorization is repeated inside the transaction

A successful lookup performed before a mutation would be only a snapshot. The session
could be revoked, expire, or lose eligibility before deletion commits. The store
therefore does not accept a previously resolved identity as deletion authority.

The implemented transaction:

1. clears previously tracked entity snapshots;
2. locks the session selected by app environment and token hash;
3. locks the associated identity selected by id and authenticated realm;
4. rechecks identity lifecycle, session purpose, revocation, and exclusive expiry;
5. discovers every linked flow id;
6. deletes those complete flow roots;
7. deletes the identity root;
8. commits both parts together.

The integration scope is not copied from a row or accepted from the request body. It
comes from the authenticated credential and is compared again when the identity is
locked. The bearer is a selector until every transactional predicate passes.

## Why `AccessFlow.IdentityId` is insufficient

An `AccessFlow` can contain personal data about more than its owning identity. During a
phone conflict, for example, a provisional identity drives the flow while conflict
state and historical snapshots can describe the earlier identity that owns the phone.
Previous-identity recovery also retains fixed references and presentation data about
both identities.

Looking only at `AccessFlow.IdentityId` would miss the earlier identity. Looking only at
current phone ownership would also be wrong because ownership may later transfer.
Searching revision JSON is not a reliable database invariant: schemas evolve, values
may be normalized or masked, and structured references can exist outside the snapshot.

`AccessFlowDataSubject` solves this as explicit, indexed reachability:

- `RealmId` keeps the attribution tenant-scoped;
- `FlowId` identifies the complete graph that may retain the data;
- `IdentityId` identifies the person to whom the retained data is attributable;
- `CreatedAt` records when that attribution first became durable;
- the composite flow-and-identity key prevents duplicate links;
- the realm, identity, and flow index supports erasure discovery.

## Append-only is an erasure invariant

Once a flow retains an identity's personal data, its data-subject link is not removed
merely because current business state changes. Phone transfer, conflict resolution,
flow completion, expiry, cancellation, or a newer revision does not rewrite older
snapshots. The historical data is still reachable and must remain discoverable.

The link disappears only with its flow graph. Treating the relation as current
ownership would create an erasure bug: removing the link after a transfer could hide a
flow that still stores the old owner's data.

Any new feature that writes an identity's data into a flow must add the corresponding
link in the same transaction. This is not optional search metadata. It is part of the
deletion contract.

## Why deleting one linked identity deletes the whole flow

Individual fields inside immutable revisions, request payload semantics, proof history,
and conflict evidence cannot be safely separated after the fact. When any linked
identity is erased, Access deletes the entire flow root and lets its dependent graph
cascade.

This can remove a flow whose `IdentityId` names another identity. That other identity is
not deleted merely because it shares the flow. Only the shared flow graph is removed.
The remaining identity, its identifiers, credentials, sessions, recovery artifacts,
and unrelated flows remain unless they are independently attributable to the erased
identity.

This trade-off favors complete erasure over preserving a partial or misleading journey
history. A client must already treat a missing flow as non-authoritative and must not
depend on historical flow availability as durable product business data.

## Records removed

Deletion has two roots with different database relationships.

### Attributable flow roots

For every flow found through `AccessFlowDataSubject`, deleting `AccessFlow` cascades to
the flow-owned graph, including:

- all data-subject links for that flow;
- immutable `AccessFlowRevision` snapshots;
- `AccessFlowRequest` idempotency records and payload hashes;
- proof challenges and their provider correlation metadata;
- immutable proof attempts;
- durable identity proofs;
- phone-registration conflict state;
- flow-owned capability, action, status, and terminal history stored on those records.

The exact schema mappings define the final list. Reviewers must update erasure tests and
this document whenever a new flow-dependent table is introduced.

### Identity root

After restrictive flow and evidence references are gone, deleting `Identity` cascades
to its directly owned Access data, including:

- normalized e-mail and phone identifiers and their verification metadata;
- password credentials;
- Google and Apple social credential links stored by Access;
- product and registration sessions, including the authorizing session;
- registration contexts;
- password reset tokens;
- phone password-reset challenges.

Topology relationships use restrictive deletion because account erasure must not
remove installation configuration. Flow, proof, and conflict relationships that can
refer to more than one identity are also restrictive from the identity side; this
forces the application to remove the attributable flow graph explicitly before the
identity cascade runs.

## Provider independence

The local deletion path performs no SMTP, SMS, Twilio, Google, or Apple operation.
Provider availability therefore cannot block the Access transaction.

Consequences include:

- an already sent reset message cannot be recalled, but its deleted local token can no
  longer be consumed by Access;
- an already sent OTP cannot be recalled, but its deleted challenge and hash can no
  longer establish proof;
- deleting an Access social credential does not delete or disable the person's Google
  or Apple account;
- provider logs and retention remain governed by those independent systems and the
  operator's agreements with them.

Do not claim that HTTP 204 proves deletion in an external provider.

## Atomicity and failure

Flow erasure and identity erasure commit in one Access PostgreSQL transaction. If the
transaction throws or is cancelled before commit, the caller must not treat either half
as successfully committed. Database constraints are a safety boundary: restrictive
references make an incomplete deletion fail rather than silently leave attributable
evidence behind.

This atomicity stops at the Access database boundary. It does not include a consumer
database or a provider. If Access is unavailable, a consumer must not claim that Access
data was deleted merely because its own profile operation succeeded. Conversely, HTTP
204 does not prove that consumer-owned data was removed.

## HTTP result and retries

| Result | Meaning | Must not be inferred |
| --- | --- | --- |
| HTTP 204 | The authorized local Access erasure transaction committed. | Consumer or provider data was deleted. |
| HTTP 401 `session-inactive` | The bearer did not authorize deletion in the fixed scope at evaluation time. | The identity definitely exists, definitely does not exist, or a previous request definitely failed. |
| Permission failure | The integration credential lacks the route permission. | The product session was inspected or changed. |
| Server/database failure | No successful local commit is confirmed to the caller. | Either half of a cross-database workflow may be assumed complete. |

Successful deletion removes every session for the identity, including the bearer that
authorized it. Repeating the request with the same token therefore returns
`session-inactive`, not another HTTP 204. After a lost response, that result is
ambiguous: the original deletion may have committed and removed the token, or the token
may otherwise be ineligible. The endpoint currently stores no post-erasure idempotency
receipt keyed by the deleted bearer.

The integrating product must choose how its own workflow records intent, retries safe
steps, and resolves ambiguous outcomes. That policy belongs outside Bullgate Access and
must not be generalized from one consumer into the shared service.

## Abandonment is not erasure

Previous-identity recovery can mark a provisional identity as `Abandoned`. That process
closes interrupted registration authority and removes usable access material, but it
retains the identity row as lifecycle history. It is not the public account-erasure
operation and must not be described as soft-delete implementation of
`DELETE /v1/account`.

Hard deletion physically removes the active identity and its attributable Access graph.
Neither operation deletes consumer-owned data. See
[`previous-identity-recovery.md`](previous-identity-recovery.md) for the distinct
continuity contract.

## Schema extension rule

Every new table or property that may retain identity data must define its erasure
ownership in the same change. Data owned directly by one identity needs an appropriate
identity relationship. Data inside a flow that describes one or more people needs a
same-transaction `AccessFlowDataSubject` link for every described identity, plus a
relationship that disappears when the complete flow is deleted.

Restrictive foreign keys should continue to make incomplete erasure fail rather than
silently retain attributable evidence. New relationships must preserve unrelated
identities and topology, and must not make local deletion depend on an external
provider.

## Guidance for AI and support answers

An answer about deletion should state, in this order:

1. Bullgate Access hard-deletes its own attributable identity graph locally.
2. An active product session selects the identity inside integration-credential scope.
3. `AccessFlowDataSubject` makes all historically attributable flows reachable.
4. Any such flow is deleted as a complete graph before the identity cascade.
5. Provider availability is not a precondition.
6. Consumer data and provider data are outside the transaction.
7. HTTP 204 confirms only the local commit, and repeating with the deleted bearer does
   not provide an idempotent success receipt.

Never answer that Bullgate Access merges databases, deletes a Google or Apple account,
waits for Twilio, searches JSON for personal data, deletes another identity merely
because it shared a flow, or treats `Abandoned` as completed erasure.

## Authoritative source map

- Domain reachability: `Domain/Flows/AccessFlowDataSubject.cs`
- Application contract: `Application/Identities/ICurrentIdentityStore.cs`
- Session-token entry point: `Application/Identities/CurrentIdentityService.cs`
- Transaction and delete order: `Infrastructure/Identities/CurrentIdentityStore.cs`
- Cascade and restrict rules: `Infrastructure/Persistence/Configurations/*`
- HTTP permission and response mapping: `Api/Endpoints/CurrentIdentityEndpoints.cs`
- End-to-end graph coverage: `IntegrationTests/CurrentIdentityAccessEndpointTests.cs`
- Non-obvious decisions: `docs/decision-catalog.md`, especially ACCESS-002,
  ACCESS-003, ACCESS-016, ACCESS-017, ACCESS-018, ACCESS-080, and ACCESS-088

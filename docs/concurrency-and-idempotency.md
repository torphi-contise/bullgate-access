# Concurrency and idempotency

Identity and verification operations cross database transactions, client retries,
and external providers. This document records which layer is authoritative when two
operations overlap or a response is lost.

## Principles

1. A service precheck improves feedback; the transactional store decides correctness.
2. A request id identifies one canonical input, not merely one endpoint invocation.
3. A revision protects a decision made from an earlier AccessFlow snapshot.
4. External effects are reserved durably before execution and finalized explicitly.
5. A timeout or canceled HTTP request does not prove that work did not commit.
6. Compensation is bounded and best-effort; persistent state remains the recovery
   authority when a provider cannot be contacted.

## Three durable records

`AccessFlow`, `AccessFlowRevision`, and `AccessFlowRequest` answer different questions:

| Record | Question answered | What it must not be treated as |
| --- | --- | --- |
| `AccessFlow` | What is the journey's current scope, authority binding, status, and revision? | The historical response to every earlier request. |
| `AccessFlowRevision` | What exact client-visible snapshot committed at one revision? | Independent authorization to execute its old actions. |
| `AccessFlowRequest` | Which canonical payload and durable result belong to this integration-scoped request id? | A globally unique request id or permission to repeat an external effect. |

The relation is:

```text
(integrationClientId, requestId)
              |
              v
      AccessFlowRequest --payloadHash--> one canonical input
              |
              +--flowId---------------> AccessFlow current state
              |
              +--resultRevision-------> exact immutable AccessFlowRevision
              |
              +--issuedSessionId------> optional persisted session hash/scope
```

The current flow may advance after a request commits. Replay still follows
`ResultRevision`; it does not substitute `AccessFlow.CurrentRevision` or reconstruct an
old answer from current policy.

## Request-id namespace and canonical payload

The durable primary key is `(IntegrationClientId, RequestId)`. The same UUID may be
used by another authenticated integration client without claiming the first client's
history. Realm, environment, and other flow scope still constrain the referenced flow.

For a start request, the canonical payload includes the offered protocol versions,
intent, public application-client key, and source session token. For an action, it
includes the flow id, expected revision, action id, action type, and action input.
Access serializes the security-relevant shape deterministically and stores a fixed-
length hash, not the clear request body.

The hash gives one request id exactly one meaning:

- same client, id, and canonical hash means exact replay;
- same client and id with another hash means `request-id-conflict`;
- another client has a separate idempotency namespace; and
- a new request id means a new operation only when current flow authority still
  advertises and accepts that operation.

Hash comparison is performed in constant time. Idempotency is not based on endpoint
path alone and does not mean that two semantically similar payloads are equivalent.

## Ordinary identity operations

Registration may check whether an email exists before constructing its graph, but the
store must enforce realm-scoped uniqueness in the creation transaction. Two parallel
registrations therefore cannot both own the same normalized email.

Password reset first checks token activity for a clear failure, then atomically
consumes the token while changing the password. The atomic consumption is the
security boundary; the preliminary read cannot prevent concurrent reuse.

E-mail recovery candidate lookup is likewise preliminary. Token issuance locks the
identity and revalidates lifecycle, realm/environment eligibility, and exact expected
e-mail ownership before inserting the hash. When an issuance constraint is supplied,
its count includes every durable reset token for the identity across environments and
channels in the window, even if a token was later used or invalidated. The constraint
therefore limits created reset authority rather than successful message delivery.

Social linking must atomically enforce:

- one credential for a provider per identity; and
- one identity owner for each provider plus provider subject.

Social unlinking must atomically ensure another authenticator remains. A service-side
count would race with a concurrent removal. The store therefore locks the identity,
loads its social credentials, and checks password availability inside the same
transaction. A missing target or last-authenticator result rolls back without changing
the credential set. This serialization prevents two concurrent unlink operations from
each observing a different credential and together removing both.

Re-linking the same provider subject is idempotent and may refresh only the provider
e-mail metadata. Re-linking that provider with a different subject is a conflict, as is
using a subject already owned by another identity. Database uniqueness remains the
authority if parallel links race after any preliminary ownership query.

## AccessFlow exact replay

For every start or action request, the client creates a request id before the first
transport attempt. Access checks an existing durable request before executing current
validation so a previously accepted result remains stable even if policy or code later
changes.

- same request id and same payload hash: return the stored result;
- same request id and different payload hash: return `request-id-conflict`;
- committed request: replay its exact stored snapshot and any deterministically derived
  session material;
- reserved, pending, or failed external request: do not repeat the provider effect just
  to manufacture a success response.

After a store reports `Committed` or `RequestAlreadyExists`, application orchestration
does not construct success from its in-memory command. It loads the durable request
that actually won the race and routes both the original caller and concurrent losers
through the same replay path.

A missing durable request after a reported commit is not accepted as success. Without
the stored payload hash and exact result revision, Access cannot verify the response,
so it returns request conflict rather than inventing state.

### Committed request

A committed request must have a positive `ResultRevision`. The database foreign key
binds `(FlowId, ResultRevision)` to the precise immutable JSON snapshot. An optional
`IssuedSessionId` may exist only for committed state.

Replay returns:

1. the stored snapshot from `ResultRevision`;
2. a flow capability derived for the current authenticated integration client and
   environment; and
3. when the request issued a session, the same clear session token deterministically
   rederived from committed server-owned scope.

Before releasing rederived session authority, Access compares its hash with the
persisted session hash. A mismatch is an internal invariant violation. The service
does not return a different token and does not store the original clear bearer merely
to make replay possible.

### Pending external request

`PendingExternal` means PostgreSQL reserved ownership before an SMS or e-mail effect,
but no successful result revision exists yet. Only the exact finalizer may continue
that reservation. A second request id does not become permission to send again.

There is at most one pending external request per flow. Challenge-backed reservations
remain live according to their challenge state and lifetime. Request-only recovery
reservations use a bounded grace period because no challenge row carries expiry.

Replay of pending state returns delivery unavailable. This is deliberately not a
claim that delivery failed: the provider call or final database commit may still be in
flight.

### Failed external request

`ExternalFailed` permanently records that this request id has no committed result
revision. Repeated failure recording is a no-op, and a failed request cannot later be
committed. Replay returns delivery unavailable without repeating the side effect.

The failure record does not prove that an external provider performed nothing. A
timeout may occur after provider acceptance, and compensation cannot create a
distributed transaction. Operator diagnosis must combine durable request, challenge,
token, and provider correlation state without exposing secrets.

### Start versus action requests

`Start` records either creation of revision one or idempotent resume of a compatible
active flow. A resume persists a request pointing to the existing immutable revision;
it does not rebuild the snapshot from current policy.

`Action` records an accepted state transition. Database-only actions are constructed
already committed inside their transaction. Provider-backed actions begin with
`ReserveExternal`, then either attach a committed revision during exact finalization or
become externally failed.

## Optimistic flow revisions

Every action carries `expectedRevision`. The store compares it while committing the
transition. A mismatch returns `revision-conflict`; the caller must refresh.

Revision one is created with the flow and start request. Every accepted active or
terminal transition increments `CurrentRevision` and inserts one matching immutable
`AccessFlowRevision` in the same transaction. Feedback-only outcomes also advance the
revision because they change the server-owned actions, retry information, or attempt
state presented to the client.

`expectedRevision` protects a decision, not just a row update. The action id and type
must also exist in the snapshot for that revision. Copying an action id into a newer
revision, or replacing the expected value with the latest number without reconsidering
the new snapshot, defeats the integration contract and is rejected.

Entity Framework marks `CurrentRevision` as a concurrency token. Domain comparison,
transactional revalidation, database row locks, and optimistic write detection work
together; an application-level precheck is not the final arbiter.

Phone ownership and conflict resolution add commit-time expectations because the
identity owning a number may change independently of the visible flow revision. Such a
change is surfaced as a conflict rather than transferring the wrong identifier.

Available action ids and types belong to a particular snapshot. Do not cache them
outside that revision or reconstruct them in a client.

## Lost responses and retry decisions

A transport timeout produces an unknown outcome. The safe decision tree is:

```text
same canonical request still available?
  -> retry with the same request id and identical payload
       -> committed: receive exact stored result
       -> pending/failed external: receive delivery-unavailable; inspect/retry by contract
       -> different hash: request-id-conflict; investigate caller id reuse

new human decision after refreshed snapshot?
  -> create a new request id for the newly advertised action
```

Do not generate a new id merely because an HTTP response was lost. That can create a
second effect after the first request already committed or remains in flight.

Exact replay is not semantic replay. Repeating previously accepted human data under a
new request id is not currently guaranteed to reproduce a terminal result. That is a
separately decided improvement and must remain labeled as not complete.

## Database invariants

PostgreSQL enforces the protocol shape in addition to service checks:

- the integration client and request id form the idempotency primary key;
- payload hashes have the required fixed length;
- a committed request has a positive result revision;
- pending and externally failed requests have neither result revision nor issued
  session;
- request result revision references a revision of the same flow;
- at most one pending external request exists per flow;
- flow revision numbers are positive and snapshots are stored as JSON objects;
- one active flow may occupy a source-session and intent slot; and
- current flow revision participates in optimistic concurrency.

These constraints turn races into named outcomes. Removing them because a service
already checks the same condition would weaken the final concurrency boundary.

## External-effect protocol

SMTP and SMS cannot participate in the PostgreSQL transaction. Operations therefore
follow this shape:

1. validate current state and reserve the operation in PostgreSQL;
2. perform the provider call;
3. finalize the durable state with the provider reference/result; or
4. record failure and attempt bounded compensation.

Cancellation after provider success is especially important. Finalization uses a
short independent cancellation budget so loss of the original HTTP request does not
discard an effect that already happened.

If finalization cannot commit, code may attempt provider cancellation or invalidate a
new reset token. These actions reduce inconsistency but are not distributed rollback.
Operators must use durable request/challenge state to diagnose an unresolved case.

Public e-mail password recovery has a narrower compensation contract. Access first
persists the reset-token hash and only then submits the clear reset URL to SMTP. SMTP
acceptance is not inbox-delivery proof, and a provider failure cannot roll back the
already committed token. Trusted orchestration receives only the token id for bounded
invalidation when a larger operation fails; the public endpoint receives neither the
token id nor the internal delivery outcome. An unsuccessful delivery may therefore
still have consumed issuance quota until that durable token expires or is invalidated.

## Phone recovery details

Phone recovery reserves rate limit, cooldown, and challenge state before sending SMS.
A replacement challenge may cancel a prior non-approved provider verification. If the
new reservation cannot be activated after delivery, Access tries to cancel that
delivery and reports it unavailable.

The phone-recovery hourly limit counts every durable request for the identity across
environments in the window, including superseded, exhausted, and delivery-failed
challenges. Cooldown likewise follows that identity's latest reserved request rather
than only the latest active challenge or current environment. Terminal state therefore
preserves abuse-control history instead of reopening quota after provider failure or
replacement.

`PendingDelivery` means only that Access owns the local reservation; its code cannot be
confirmed. `Active` begins only after delivery state is attached durably. A locally
matched code moves to `Confirming`, which is an exclusive reservation while provider
approval occurs outside PostgreSQL. `Completed` is written only in the same transaction
that records provider approval and persists the resulting reset-token hash.

If replacement delivery cannot proceed, rollback may restore the superseded predecessor
only when it is unexpired and has a provider reference. A pending reservation, expired
predecessor, or provider-less predecessor is not guessed back into an active state.

Confirmation first reserves the challenge for one confirmer, then performs provider
approval when configured, then creates and stores reset authority. On provider failure
the confirmation reservation is released so a valid retry can proceed.

## Integration checklist

- Generate request ids once at the controller/SDK boundary and persist them across
  transport retries.
- Serialize one in-flight mutation per user journey where practical.
- Never translate a timeout into unconditional request-id regeneration.
- Refresh after revision conflict and use only newly advertised actions.
- Respect resend and rate-limit timestamps from server state.
- Keep flow capability and identity session tokens in the BFF.
- Record correlation metadata, never bearer material or OTP values.
- Test response-loss cases in addition to explicit provider failures.

See [`access-flow.md`](access-flow.md), [`failure-model.md`](failure-model.md), and
the cross-cutting [`decision catalog`](decision-catalog.md).

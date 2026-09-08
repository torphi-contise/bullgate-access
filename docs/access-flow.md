# AccessFlow protocol

`AccessFlow` is the persistent protocol for identity journeys that cannot be
represented safely as one request. Protocol version 1 implements
`continueRegistration` and `managePhone`. Protocol version 2 adds required CPF
and birth-date collection to `continueRegistration`; a client that does not
advertise version 2 cannot start that configured journey.

## Why a server-owned state machine

A consumer screen cannot safely decide whether a phone can be collected,
verified, transferred, skipped, or used for recovery. Those choices depend on
environment policy, identity ownership, proof state, source-session validity,
rate limits, and concurrent requests.

The server therefore returns the current step and a closed list of actions. The
client renders that semantic state and submits one advertised action at the
expected revision.

## Scope and authority

Every flow is bound to:

- integration client, environment, and realm from server authentication;
- application client selected by stable public key;
- current identity and source session;
- intent and protocol version;
- expiration and optimistic revision.

PostgreSQL also enforces that only one active flow may use the same source session and
intent. Completion or expiry leaves historical flows available while releasing that
active slot for a later journey.

The opaque flow capability authorizes access to one flow. A BFF keeps it in a
path-scoped `HttpOnly` cookie or equivalent server storage. Knowing `flowId` is
not authorization. Read and action requests require exactly one capability value
bound to that flow, integration client, and app environment in addition to the
authenticated integration scope. Missing, malformed, incorrectly scoped, and
non-matching capability cases collapse to `flow-not-found`.

## Intent-specific conditions

### `continueRegistration`

Requires an active registration-purpose source session and an open
`RegistrationContext`. A successful terminal action closes the context, revokes
registration sessions tied to it, and issues a product session.

The context id is only a state reference. It is not a flow capability or session
bearer, and a closed context cannot be reopened or changed to another terminal outcome.

### `managePhone`

Requires an active product session. It deliberately has no
`RegistrationContext`: manufacturing one would confuse an authenticated account
operation with unfinished registration.

## Starting and resuming

Candidate and active-flow reads are planning inputs, not authorization. The
creation transaction locks and revalidates the identity, source session,
registration context when applicable, request id, and active source/intent slot.
A partial unique index is the final arbiter when two creators race.

Only one active flow may use a source-session and intent pair. A compatible flow
is resumed only when its identity, realm, environment, protocol, registration
context, integration client, and public application client still match. Resume
records the new start request against the existing current revision and returns
that persisted snapshot verbatim; it does not rebuild an in-progress journey
from newer policy. An incompatible owner receives a scoped conflict instead of
having the flow transferred or silently replaced.

## Revisions and action availability

Revision starts at 1. Every accepted transition advances it. An action includes
the revision observed by the client. If current state advanced meanwhile, the
store rejects the stale request and the client refreshes the snapshot.

Action presence is authorization for that revision. A client must not infer an
action from the step name, retain an action id across revisions, or guess a
terminal transition.

`skipRegistration` follows the same rule. It appears only on
`continueRegistration` snapshots when the environment policy makes phone
collection optional. Omitting the action is a denial, not a presentation hint;
submitting a fabricated or stale skip action is rejected.

## Request replay

`requestId` is scoped to the integration client and stored with a canonical
payload hash. Three cases are distinct:

1. unseen id: arbitrate and execute the request;
2. known id, same payload: return the stored result;
3. known id, different payload: return request-id conflict.

This is exact replay. Semantic replay under a new id after a terminal human
confirmation is a separately decided improvement and must not be claimed as
already implemented.

A committed request stores a foreign key to the precise revision returned to the
caller. Later transitions do not change replay output. A partial unique index permits
only one pending external request per flow, making ownership of an in-flight provider
effect unambiguous.

When a committed request issued a product session, replay derives the clear token
again from the committed flow, request, identity, and environment scope. Before
returning it, Access compares the derived hash in constant time with the session
hash referenced by that request. A mismatch is an internal invariant failure; the
service does not return a newly derived but unverified bearer. The clear token is
never loaded from PostgreSQL because it was never stored there.

While that reservation is live, changing `requestId` does not grant permission to
repeat or bypass its provider effect. Its own finalizer may continue the exact
pending request, but another action receives a pending-external outcome. Replaying
the same pending or failed request also does not perform delivery again.

A challenge-backed reservation remains live while its challenge can still be
finalized. Previous-identity recovery has no challenge row, so its request-only
reservation uses a one-minute grace window. After the applicable lifetime ends,
the next locked reconciliation marks the orphaned request failed and either fails
delivery or releases confirmation state before allowing a new transition. This
recovery rule prevents a crashed worker from blocking the flow forever without
treating a new request id as immediate duplicate-delivery authority.

## Terminal session rotation

A normal terminal action commits the terminal snapshot, the idempotency result,
the new product-session hash, and revocation of the source session in one
transaction. The clear product token is derived deterministically from trusted
flow and request scope, so exact replay can reproduce it without storing clear
bearer authority.

Registration completion also closes the `RegistrationContext` and revokes other
active registration sessions for the same identity and environment. Phone
management rotates the product session that authorized that flow but does not
globally sign out the identity's other product sessions.

## Expiration and replacement

Expiration is a revisioned terminal transition, not a timestamp-only overwrite.
The store locks the same identity and source-session authority used by ordinary
actions, requires the exact current revision, closes pending local reservations
and challenge states, and persists an expired snapshot. If another transition
wins first, the caller returns that durable snapshot instead of claiming its own
expiration succeeded.

An expired flow releases the unique active slot for its source session and
intent. It does not revoke that source session, so a still-active session may
start a replacement flow. Closing local coordination state cannot retract an
e-mail or message already accepted by an external provider.

## Phone verification sequence

```text
collectPhone
  -> request/submit phone
  -> reserve challenge
  -> deliver custom OTP
  -> finalize delivery
  -> verifyPhone
  -> begin confirmation reservation
  -> compare local secret hash
  -> record failed attempt, complete, or create conflict
```

Delivery and database commit are separate failure domains. The reservation is
created before calling the provider so a sent or failed message never becomes
invisible to replay logic.

The local hash is authoritative in `AccessFlow`. Twilio carries the custom code;
Access does not ask it to make a second confirmation decision after the local
code matches.

## CPF and birth-date sequence

When CPF policy is enabled, the configured `cpfCollectionPosition` places the
combined step before or after phone collection. `collectCpf` advertises only
`submitCpf`. The action accepts `cpf` and `birthDate` together. Invalid CPF
or birth date returns the same step with field-specific feedback and stores
neither value.

A valid action atomically stores the realm-unique normalized CPF and identity
birth date. With `beforePhone`, registration starts at `collectCpf` and advances
to `collectPhone` if phone is enabled; otherwise it completes registration.
With `afterPhone`, phone must be enabled and required. Registration starts at
`collectPhone`; collecting or verifying the phone advances to `collectCpf`
without issuing a product session or closing the registration context. Submitting
both civil fields then completes registration and issues the product session.

The existing phone-conflict decision and previous-email comparison are unchanged.
With `afterPhone`, successful phone transfer continues to `collectCpf` instead of
completing registration immediately. CPF does not resolve the conflict or enable
email replacement. CPF is stored without verification metadata because structural
check digits do not establish ownership.

The full distinction between challenge state, attempt history, durable proof,
identifier verification, and identifier ownership is defined in
[`proof-lifecycle.md`](proof-lifecycle.md).

## Conflict decisions

If the proven phone belongs to another identity, the server enters
`resolvePhoneConflict`. Depending on intent and policy it may advertise:

- `changePhone` — discard the current choice and collect another phone;
- `transferPhoneToCurrentIdentity` — require knowledge of the previous email
  and move only the proven phone;
- `recoverPreviousIdentity` — reserve and send normal password recovery for the
  previous identity, then abandon the provisional registration identity;
- `skipRegistration` — only when registration policy permits omission.

None of these actions silently merges two identities or copies both sets of
credentials.

`recoverPreviousIdentity` crosses a database/e-mail boundary. Access first
reserves the idempotent action, then requests password recovery for the stored
previous identity by id, and only after provider acceptance does it abandon the
provisional registration identity and complete the flow. If delivery or final
persistence fails, Access marks the reservation failed and, when it received a
token id, makes a bounded best-effort attempt to consume that reset token. This
compensation cannot make the database and provider one transaction, and provider
acceptance does not prove inbox delivery.

The complete availability, state, failure, integration, and AI-answer contract for this
feature is in
[`previous-identity-recovery.md`](previous-identity-recovery.md).

## Erasure reachability

A flow can retain data about more than its owning identity. Whenever it starts
retaining another identity's data, the same transaction adds an
`AccessFlowDataSubject` link. The link is append-only because later transfer or
state changes do not erase the historical fact that the flow holds data.

Hard deletion follows these links and purges the complete flow graph, including
revisions, requests, payload hashes, challenges, attempts, proofs, conflicts,
and snapshots. It can remove a flow whose owner is another identity, but it does not
delete that other identity. See [`identity-erasure.md`](identity-erasure.md) for the
full reachability and transaction contract.

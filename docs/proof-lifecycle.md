# Proof challenge and identity-proof lifecycle

This document defines how Bullgate Access represents possession proof. It is the
canonical source for questions about generated codes, provider delivery, attempt
accounting, successful confirmation, and durable proof evidence.

Read it with [`access-flow.md`](access-flow.md) for protocol sequencing and
[`security-model.md`](security-model.md) for trust boundaries.

## Core rule

Possession is not inferred from syntax, matching text, current identifier ownership,
or provider acceptance of a delivery request. Access records possession only when an
eligible challenge secret is successfully compared and the corresponding proof is
committed under the current flow authority.

Four facts must remain distinct:

1. an `IdentityIdentifier` stores a canonical e-mail or phone and its current owner;
2. a `ProofChallenge` represents temporary authority to attempt one proof;
3. a `ProofAttempt` records one comparison that committed; and
4. an `IdentityProof` records the durable fact established by successful confirmation.

Changing one fact does not silently invent the others.

## Records and ownership

### `ProofChallenge`

A challenge belongs to one `AccessFlow` and one flow identity. It fixes:

- the proof type;
- delivery channel;
- canonical destination scheme and value;
- hash of the generated secret;
- optional provider correlation reference;
- committed failed-attempt count and configured maximum;
- creation, expiry, and resend-cooldown times; and
- lifecycle status and optional terminal time.

The clear one-time code is never stored. `SecretHash` is the local comparison
authority. `ProviderReference` helps correlate or compensate provider work but does
not prove that the person received, read, or submitted the code.

### `ProofAttempt`

An attempt is an append-only record linked to the challenge. `Failed` means one wrong
comparison consumed capacity. `Succeeded` means the successful comparison and its
downstream proof transaction committed.

An attempt row alone is not authorization and must not be interpreted without the
challenge and, for success, the matching `IdentityProof`.

### `IdentityProof`

An identity proof is immutable evidence linked to one flow, flow identity, challenge,
proof type, and optional subject identifier. The database permits one proof per
challenge.

For phone possession, `IdentityId` answers **who performed the proof**, while
`SubjectIdentifierId` answers **which exact phone identifier was proven**. During a
phone conflict, that identifier may still be owned by the previous identity. This is
intentional: proof of current possession does not itself transfer ownership or merge
identity histories.

## Challenge states

| State | Meaning | May authorize an attempt? |
| --- | --- | --- |
| `PendingDelivery` | The database reserved provider work, but delivery is not yet usable. | No |
| `Active` | Delivery was finalized and the challenge is within its attempt lifetime. | Yes |
| `Confirming` | One successful comparison exclusively owns finalization. | No second caller may proceed |
| `DeliveryFailed` | Provider delivery failed before activation. | No |
| `Verified` | Successful confirmation committed. | No; terminal |
| `Superseded` | Replacement or enclosing lifecycle work closed the challenge. | No; terminal |
| `Exhausted` | The final permitted wrong comparison committed. | No; terminal |

The principal transitions are:

```text
PendingDelivery --provider accepted and local finalization committed--> Active
PendingDelivery --delivery/finalization failed------------------------> DeliveryFailed

Active --wrong code below limit---------------------------------------> Active
Active --final permitted wrong code----------------------------------> Exhausted
Active --successful local comparison reserved------------------------> Confirming
Active --replacement or enclosing transition-------------------------> Superseded

Confirming --proof transaction committed-----------------------------> Verified
Confirming --finalization released before expiry---------------------> Active
Confirming --released at or after expiry-----------------------------> Superseded
```

Terminal states never return to active authority.

## Delivery sequence

External delivery cannot participate in the PostgreSQL transaction. Access therefore
uses a reserve, send, and finalize sequence:

1. normalize and validate the requested destination;
2. derive the current flow, source session, realm, environment, and client scope;
3. generate the clear code in application memory and persist only its hash;
4. reserve a `PendingDelivery` challenge and a pending idempotent request;
5. call the configured delivery provider;
6. on provider success, lock and revalidate the exact reservation;
7. supersede an older active challenge only now;
8. activate the replacement, persist its provider reference, advance the flow
   revision, and commit the request together; or
9. on failure, mark only the new reservation `DeliveryFailed` and retain any older
   active challenge.

This ordering prevents a failed resend from destroying the only code that was still
usable. It also prevents a successful provider call from becoming challenge authority
without matching local state.

Provider acceptance is not proof of handset delivery. If finalization becomes
uncertain, clients use request replay and the current server-owned snapshot rather than
assuming that a particular code is active.

## Resend and rate limits

The current active challenge supplies the resend-cooldown boundary. A request before
`ResendAvailableAt` does not create another provider operation.

AccessFlow challenge-rate accounting counts durable requests for the identity and
proof type inside the configured window, except challenges whose delivery is recorded
as `DeliveryFailed`. That exception is deliberate: an unusable provider failure must
not consume the person's AccessFlow proof capacity.

This rule is specific to AccessFlow proof challenges. Other recovery stores may count
provider failures or terminal requests differently. An integrator or assistant must
not generalize one rate-limit policy to every recovery channel.

## Failed comparison sequence

The application hashes a submitted code and compares it with `SecretHash` using a
fixed-time comparison. A mismatch is not committed from the preliminary read alone.
The store locks and revalidates:

- authenticated integration scope;
- flow and expected revision;
- source identity and session authority;
- exact active challenge and its flow identity;
- exclusive expiry boundary; and
- expected failed-attempt count.

The store then commits the increment, `ProofAttempt(Failed)`, feedback snapshot,
request result, and new flow revision together. Optimistic attempt checking prevents
two concurrent submissions based on the same snapshot from both consuming the same
next attempt number.

At `MaxAttempts`, the challenge becomes `Exhausted`. The next snapshot returns to an
eligible collection or replacement path instead of continuing to advertise a dead
challenge.

## Successful confirmation sequence

A local code match is necessary but not sufficient to commit proof. Before reserving
confirmation, the store locks the challenge and rechecks its identity, destination,
status, expiry, expected attempt count, flow revision, and current phone ownership.

`BeginConfirmation` changes `Active` to `Confirming` and creates a pending request.
This grants one request exclusive ownership of final proof materialization. A second
request cannot consume the same successful comparison.

Finalization revalidates the reservation and current ownership again. One transaction
then commits the applicable combination of:

- `ProofAttempt(Succeeded)`;
- one `IdentityProof`;
- `ProofChallenge.Verified`;
- creation or verification of the phone identifier;
- a `PhoneRegistrationConflict` when another active identity owns the proven phone;
- the next or terminal flow snapshot;
- source-session revocation and a replacement product session when the journey
  completes; and
- the committed idempotent request result.

For AccessFlow phone confirmation, Twilio transports the custom code but is not asked
to decide its validity. Access generated the secret and owns its hash, attempt budget,
and confirmation transaction.

## Confirmation failure and release

If final persistence fails after confirmation was reserved, Access makes a bounded
attempt to release the exact request and challenge. A release before expiry returns the
challenge to `Active`; a release at or after expiry closes it as `Superseded`.

Release is compensation, not distributed rollback. When the durable outcome remains
uncertain, clients must retrieve or replay server state. They must not retry with a new
request id merely because an HTTP connection ended.

## Identifier ownership is separate

A successful phone proof may have three different outcomes:

- create a new verified phone identifier for the current identity;
- verify an existing phone identifier already owned by the current identity; or
- record a conflict because the exact verified identifier belongs to another active
  identity.

The proof does not choose among transfer, recovery, change-phone, or optional skip.
Those are later actions advertised by the current AccessFlow snapshot. A phone conflict
never authorizes an automatic identity merge.

## Database invariants

PostgreSQL complements domain checks with:

- non-negative attempts not exceeding a positive maximum;
- expiry after creation and resend time not before creation;
- no terminal completion time on open states and a required completion time on
  terminal states;
- fixed secret-hash length;
- at most one `Active`, one `PendingDelivery`, and one `Confirming` challenge for a
  flow and proof type;
- one `IdentityProof` per challenge; and
- foreign keys tying attempts and proofs to their exact challenge, flow, identity, and
  optional subject identifier.

Partial unique indexes are the final arbitration layer when concurrent workers passed
earlier reads. Application checks improve error mapping; they do not replace database
constraints.

## Deletion and retained evidence

Challenges, attempts, and proofs are Access-owned identity data. Flow reachability and
foreign keys ensure identity deletion can remove attributable proof state without
searching serialized snapshots. Consumer profiles and business data remain outside
this transaction.

Do not copy clear codes, hashes, provider credentials, or private provider payloads
into logs, documentation, support tickets, or retrieval corpora.

## Integration rules

- Execute only actions advertised by the latest snapshot.
- Treat a flow id, challenge id, and action id as selectors, not standalone authority.
- Keep flow capability and session bearers in the server-side BFF.
- Reuse the same request id only with the exact same payload.
- Treat delivery acceptance and HTTP success separately from durable proof completion.
- Use returned feedback and retry times; do not invent client-side attempt counters.
- Never infer possession from a non-null phone, matching text, or provider reference.

## AI grounding rules

When answering questions about proof, retrieve this document plus the current domain
types and store transaction involved. Preserve these distinctions:

- challenge is temporary attempt authority;
- attempt is a committed comparison fact;
- identity proof is durable completed evidence;
- identifier verification is metadata on the canonical identifier;
- identifier ownership may differ from the identity that just proved possession during
  conflict resolution; and
- provider delivery is transport, not local proof authority.

Never claim that a sent SMS proves possession, a successful attempt row alone grants a
session, or an `IdentityProof` automatically merges identities or transfers an
identifier.

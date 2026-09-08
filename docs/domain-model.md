# Domain model

The [administrative backend](administration.md) adds the Access-owned
`AdminOperation` committed receipt. It records trusted Admin attribution,
function/target, UTC time, a purpose-keyed input fingerprint and secret-free
result. It contains no human profile database or current user contact data and
has no cascading identity relationship, so erasure can retain its receipt.

## Topology

Topology establishes isolation before an identity operation occurs. Natural
keys make bootstrap idempotent; UUIDs remain internal primary keys.

An app and a realm each belong to one workspace. Composite database foreign keys
require an `AppEnvironment` to reference an app and realm from that same workspace;
valid individual UUIDs cannot be combined across workspace boundaries.

An `AppEnvironment` is the policy and configuration unit. It references a
realm, stores queryable policy flags, and stores the complete provider document
as AES-256-GCM protected data.

## Identity and identifiers

An `Identity` represents one person recognized inside a realm. `Active`
identities can authenticate. `Abandoned` identifies a provisional identity
closed while recovering a previous identity. User-requested deletion is not an
abandoned state; it is a hard delete.

Abandonment retains the provisional identity row as closed lifecycle history. The
recovery transaction revokes its sessions and removes its credentials, identifiers,
recovery artifacts, and current-flow proof state. It must not be presented as erasure.

`IdentityIdentifier` associates an identity with a normalized `email`, `cpf`, or
`phone`. `RealmId + Scheme + NormalizedValue` is unique. Email acceptance is
policy-driven. Phone possession is a separate proof-based contract. An identity
also stores an optional birth date; CPF policy collects and commits both values
together, while only CPF participates in identifier uniqueness.

The CPF normalizer accepts eleven ASCII digits or the canonical dotted form,
rejects repeated digits, and validates both check digits. Birth date accepts the
exact ISO `yyyy-MM-dd` calendar form and cannot be in the future. Structural CPF
validation is not government verification or proof that the person owns the CPF.

The current phone normalizer accepts an already canonical international shape:
`+`, a non-zero first digit, and 8–15 ASCII digits in total. It trims only outer
whitespace; it does not infer a country, remove punctuation, validate number
allocation, prove reachability, or prove possession. When policy enables phone
verification, possession is established separately through the proof journey.

Each identity also has at most one identifier for a given scheme in a realm. These
two uniqueness rules are distinct: one prevents two identities from owning the same
normalized value, while the other prevents ambiguous primary e-mails or phones on a
single identity.

## Authenticators and sessions

`PasswordCredential` stores a password hash. `SocialCredential` stores a
validated Google or Apple subject within a realm. Re-linking a subject to its
current identity is idempotent. A subject owned by another identity is a
conflict, not permission to merge identities.

`IdentitySession` belongs to an identity and environment and stores only a token
hash. A `Registration` session is restricted to finishing registration. A
`Product` session can be resolved by a consumer BFF into a local principal.

Session-token hashes are globally unique. Environment remains an authorization scope,
but it is not used to make a duplicate bearer value acceptable. Deleting an identity
cascades to its sessions and authenticators; deleting topology is restricted and uses
explicit lifecycle changes instead.

## Registration, proofs, and conflicts

`RegistrationContext` records whether registration in one environment is open,
completed, or abandoned. `ContinueRegistration` requires it; `ManagePhone`
starts from a product session and must not have one.

The context is persisted registration state, not a session token or an `AccessFlow`.
It closes monotonically: replaying the same terminal outcome preserves the original
closure time, while changing `Completed` to `Abandoned` or the reverse is rejected.

Password login does not bypass this boundary. When an identity still has an open
registration context in the target environment, a successful password check issues
another registration-purpose session. Likewise, an enabled but optional phone policy
keeps a new registration context open until the server-owned flow records either
phone collection or the explicitly advertised `skipRegistration` action.

`ProofChallenge` stores a destination, secret hash, provider reference, attempt
limit, expiry, resend cooldown, and state. `ProofAttempt` records committed
comparisons. `IdentityProof` materializes completed evidence. These records are
not interchangeable with identifier ownership or verification metadata. See
[`proof-lifecycle.md`](proof-lifecycle.md) for the complete transition and
transaction contract.

The database permits historical terminal challenges while partial unique indexes
allow at most one active, pending-delivery, or confirming challenge for the same
flow and proof type. A challenge can materialize at most one `IdentityProof`.
These constraints are the final concurrency boundary when two workers observe the
same earlier state.

For an `AccessFlow` phone challenge, the local secret hash is the acceptance
authority. Twilio transports the generated custom code; it is not queried again
to decide whether a locally matched code is valid.

`PhoneRegistrationConflict` records that a proven phone belongs to another
identity. Current resolutions can return to collection, transfer only the phone
after checking the previous email, or request recovery where the intent permits
it. Transfer preserves that phone's normalized value and existing possession proof;
it changes the identifier owner but does not merge identity histories.

There is at most one phone-registration conflict per flow. The conflict references
the previous identity and its phone identifier with restrictive foreign keys so the
evidence cannot disappear independently; deleting the owning flow removes the
conflict.

## Recovery and AccessFlow

Email and phone recovery converge on a single-use `PasswordResetToken` stored
by hash. Phone recovery first uses a `PhonePasswordResetChallenge`. Recovery
responses avoid identifier enumeration, and contact changes invalidate
artifacts tied to the previous contact.

`UsedAt` is the shared terminal marker for successful reset consumption and
compensating invalidation. It means the bearer can no longer reset a password; it does
not, by itself, prove that password replacement occurred. Repeating domain consumption
is invalid, while store-level invalidation is a conditional, retry-safe operation.

For phone recovery, only one pending-delivery, active, or confirming challenge may
exist per identity and environment. A locally completed challenge must have a
recorded provider approval time. This preserves the reserve/deliver/finalize order
across database and provider failure boundaries.

An `AccessFlow` binds scope, identity, source session, intent, protocol version,
revision, and expiry. `AccessFlowRevision` stores a response snapshot.
`AccessFlowRequest` binds `requestId` to a payload hash and result. Same id plus
same input reproduces the result; same id plus different input is a conflict.
The current flow revision and a request's result revision may differ after later
transitions; exact replay always follows the latter. The complete contract is in
[`concurrency-and-idempotency.md`](concurrency-and-idempotency.md).

Only one active flow for a source session and intent may exist at once. Terminal flows
remain as history. Each committed request references the exact immutable revision it
returned, so replay does not drift to the flow's newest snapshot. At most one request
per flow may own a pending external effect.

`AccessFlowDataSubject` is an append-only reachability relation to every
identity whose personal data the flow retains. Hard deletion uses it to remove
entire related flows without searching serialized JSON or relying on current
identifier ownership. A shared flow can be deleted because one subject is erased
without deleting the other linked identities. The complete graph and ownership
contract is in [`identity-erasure.md`](identity-erasure.md).

## Cross-cutting invariants

- Domain timestamps use UTC offset zero.
- Empty UUIDs are rejected at domain boundaries.
- Passwords, tokens, codes, and client secrets are stored only as hashes.
- Email, CPF, and phone are normalized before uniqueness checks; normalization is not
  possession proof.
- Realm and environment scope comes from authenticated context.
- State transitions reject stale revisions.
- External effects are not presented as atomic with PostgreSQL.
- Deletion does not depend on a provider being available.

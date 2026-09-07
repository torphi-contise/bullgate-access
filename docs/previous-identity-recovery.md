# Previous identity recovery

## Status and purpose

Previous-identity recovery is **implemented** in AccessFlow protocol version 1 for
the `continueRegistration` intent. It handles a specific continuity problem: a person
starts a new registration, proves possession of a phone, and Access discovers that the
same verified phone is already owned by another active identity in the realm.

The feature offers a safe route back to that previous identity. It does not merge two
identity histories, copy credentials, transfer a consumer profile, or authenticate the
previous identity immediately. Access sends the normal password-recovery path to the
previous identity's stored e-mail and closes the provisional registration only after
the delivery provider accepts the message and final persistence succeeds.

This document describes current source behavior. Consumer user-interface wording and
consumer-profile reconciliation remain responsibilities of the integrating product.

## The two identities

Use these terms consistently:

| Term | Meaning | Result of successful flow finalization |
| --- | --- | --- |
| Previous identity | Active identity that already owns the verified phone. | Remains active and keeps the phone and its existing identity history. |
| Provisional identity | New identity created by the interrupted registration flow. | Becomes `Abandoned` and loses its usable authentication, identifier, and recovery paths. |
| Consumer profile | Product-owned business record associated separately with an Access identity. | Not merged, transferred, or deleted by the Access transaction. |

The words "current identity" in source commands and terminal fields refer to the
provisional identity currently driving the flow. They do not mean that this identity
will be retained after recovery.

## How the conflict is created

Recovery is not offered merely because two records contain similar text. The flow must
first complete its phone-possession challenge using the locally stored secret hash.
At confirmation time, Access discovers that the exact normalized phone identifier:

- belongs to a different identity in the same realm;
- has existing possession-verification evidence;
- is still associated with an active previous identity; and
- is the subject of a new durable phone-possession proof produced by the current flow.

Access then stores one `PhoneRegistrationConflict` for the flow. The conflict fixes the
expected previous identity id and phone-identifier id, expires no later than the flow,
and records the bounded e-mail-knowledge attempts used by the separate phone-transfer
choice.

This proof does not authorize an identity merge. It establishes that the person driving
the provisional flow currently possesses a phone already associated with an earlier
identity.

## When `recoverPreviousIdentity` is available

The action is server-advertised only in a current `resolvePhoneConflict` snapshot when:

- the flow intent is `continueRegistration`, not `managePhone`;
- the source registration session, registration context, flow capability, integration
  scope, application client, revision, and action id/type remain valid;
- the conflict is present and has not expired;
- the previous identity is still active in the same realm;
- the phone is still verified and owned by that previous identity;
- the current flow still has its durable proof for that exact phone identifier.

The e-mail-knowledge attempt budget belongs only to
`transferPhoneToCurrentIdentity`. After that budget is exhausted, transfer disappears
but `recoverPreviousIdentity` remains available. Recovery accepts no caller-selected
address and delivers only to the previous identity's stored canonical e-mail, so the
person must still prove mailbox possession. The other choices depend on registration
policy and may include `changePhone` or `skipRegistration`.

`managePhone` deliberately does not offer previous-identity recovery. It begins with an
established product identity; its conflict choices may move the proven phone or select
another phone, but they do not abandon that product identity in favor of another one.

The client must never manufacture this action. It may execute only the action id and
type present in the latest authorized snapshot.

## End-to-end sequence

```text
provisional registration identity
  -> prove possession of phone
  -> phone is verified and owned by previous active identity
  -> resolvePhoneConflict snapshot
  -> choose advertised recoverPreviousIdentity action
  -> reserve idempotent external operation in PostgreSQL
  -> select previous identity and e-mail from locked/server-owned state
  -> issue reset token hash under normal recovery limits
  -> send the only clear reset URL through the e-mail provider
  -> provider accepts the message operation
  -> revalidate conflict, identities, phone ownership, and proof
  -> abandon provisional identity and registration context
  -> complete flow with previousIdentityRecoveryRequested
  -> person uses reset link and later authenticates as previous identity
```

The action has no client-controlled recovery destination. The BFF sends the normal
action envelope—new `requestId`, current `expectedRevision`, and the advertised action
id/type—but no e-mail or previous identity id can redirect the message. Trusted
orchestration resolves the previous identity from `PhoneRegistrationConflict`, then
loads its current canonical e-mail inside the authenticated realm and environment.

## What each signal proves

| Signal | It proves | It does not prove |
| --- | --- | --- |
| Current-flow phone proof | The provisional flow completed Access's phone-possession contract for the exact conflicting identifier. | Permission to merge histories or ownership of the previous e-mail inbox. |
| Masked previous-e-mail hint | A presentation hint derived from stored state, when an e-mail exists. | Mailbox possession, identity authority, or a valid delivery target supplied by the client. |
| Pending external request | One integration-client request owns the attempt to produce the external effect. | That a token was issued or an e-mail was accepted. |
| Issued token id | Trusted compensation can target one reset-token row without receiving the clear bearer. | Reset authority, SMTP acceptance, or inbox delivery. |
| Provider `Sent` outcome | The configured e-mail adapter accepted the message operation. | Inbox delivery, link use, password replacement, or authentication. |
| Terminal AccessFlow result | The local finalization transaction committed after provider acceptance. | That the person used the reset link or that consumer data changed atomically. |
| Reset-token consumption | The previous identity's password was replaced and its competing Access credential paths were invalidated. | Automatic creation or selection of a consumer profile. |

## Reserve, deliver, and finalize

PostgreSQL and the e-mail provider cannot participate in one atomic transaction. The
implementation therefore uses three explicit phases.

### 1. Reserve

The store starts a transaction and revalidates the active flow, expected revision,
registration context, source session, integration scope, previous identity, conflict,
phone ownership, phone verification, and current-flow proof under the required locks.
It then persists an `AccessFlowRequest` in `PendingExternal` state.

The request id is scoped to the authenticated integration client and bound to the exact
payload hash. A partial unique index permits only one live external-operation reservation
for the flow. The flow revision does not advance during reservation.

### 2. Issue and deliver

Trusted orchestration requests password recovery by previous identity id, not by a
client-supplied e-mail. Standard e-mail recovery then revalidates that the identity,
realm, environment, current e-mail, password feature, recovery URL, and sender are
eligible. The identity-wide issuance limit counts durable reset tokens across
environments and recovery channels.

The reset token hash is committed before the provider call. The clear bearer exists
only inside the reset URL passed to the e-mail delivery boundary. The AccessFlow
coordinator receives only the durable token id for possible bounded invalidation.

### 3. Finalize

After provider acceptance, finalization uses a short cancellation token independent of
the original HTTP request. A disconnected application must not by itself strand a
provider effect that already happened.

The store locks and revalidates the same conflict, identity, phone, and proof facts used
during reservation. Provider acceptance alone is insufficient. If those facts still
qualify, one PostgreSQL transaction:

- marks the provisional identity `Abandoned`;
- marks its `RegistrationContext` `Abandoned`;
- completes the AccessFlow and writes its terminal revision;
- commits the exact idempotency request to that revision;
- removes the resolved `PhoneRegistrationConflict`;
- revokes the provisional source session and its other sessions;
- removes the provisional identity's password credentials, social credentials,
  identifiers, reset tokens, phone-recovery challenges, and current-flow proof state;
  and
- preserves the previous active identity and its verified phone.

The terminal snapshot has `status: completed`, no available actions, and a result with:

```json
{
  "type": "registrationAbandoned",
  "outcome": "previousIdentityRecoveryRequested",
  "previousIdentityId": "00000000-0000-0000-0000-000000000001",
  "currentIdentityId": "00000000-0000-0000-0000-000000000002"
}
```

The UUIDs above are non-secret placeholders. `previousIdentityId` is the retained
identity; `currentIdentityId` is the abandoned provisional identity.

No product session is issued by this terminal transition. The previous identity's
password and sessions are not changed merely because the e-mail was requested. If the
person uses the reset link, the separate password-reset transaction replaces the
password, consumes competing reset tokens, and revokes all sessions for the previous
identity. The person may then authenticate through the normal login contract.

## Failure and retry behavior

| Situation | Current behavior | Integration rule |
| --- | --- | --- |
| Action is no longer advertised or conflict eligibility changed | Returns an action/state conflict such as `action-not-available` or a revision conflict. | Fetch the latest snapshot and render only its actions. |
| Password-recovery issuance limit is reached | Returns `password-recovery-rate-limited`. | Do not fan out retries; follow the product's bounded retry handling. |
| Recovery URL, sender, or provider is unavailable | Returns `password-recovery-unavailable`; any issued token id is submitted for bounded invalidation. | Treat the operation as failed, but do not claim external rollback. |
| Another request owns a live external effect | The pending reservation prevents duplicate delivery. | Retry the exact request before inventing a new request id. |
| Provider accepts e-mail and finalization commits | Exact replay returns the persisted terminal result. | Reuse the same request id only for the same payload. |
| Provider accepts e-mail but finalization fails | Access tries to invalidate the exact token and mark the reservation failed using short independent budgets. | Treat outcome as operationally uncertain; the e-mail cannot be retracted. |
| Token invalidation compensation also fails | A delivered reset link may remain usable until consumed, invalidated elsewhere, or expired. | Diagnose durable request/token state; never report that rollback succeeded. |
| Original HTTP request is cancelled after provider acceptance | Bounded finalization continues independently. | Do not interpret client disconnect as proof of failure. |

Request-only e-mail reservations have no proof-challenge row to define their lifetime.
The current store treats them as live for a short one-minute grace window. Locked
reconciliation can close stale local state so a crashed worker does not block the flow
forever. This is duplicate-delivery control, not a promise that an e-mail completes in
one minute.

## Consumer integration contract

The consumer BFF must:

- keep the integration credential, registration session, and flow capability
  server-side;
- submit exactly the action id/type from the latest snapshot with the matching revision;
- generate a new request id for a new action and reuse it only for an exact retry;
- never ask the application client for a previous identity id or recovery e-mail;
- present masked hints only as hints, never as proof;
- treat the terminal result as recovery requested, not recovery completed or login
  completed;
- avoid creating a product-authenticated session from the terminal flow result;
- resolve the previous identity only after normal Access authentication later succeeds;
- define separately how its own profile association and business data should respond;
  and
- preserve unknown outcomes for retry/support rather than silently starting another
  delivery attempt.

The application user interface should explain that the new registration was closed and
that recovery instructions were sent to the e-mail already associated with the earlier
account. It must not claim that Access merged accounts, moved purchases, transferred a
consumer profile, delivered an e-mail to the inbox, or completed a password reset.

## Data ownership and erasure

The flow may retain personal data about both identities. `AccessFlowDataSubject` links
make that erasure reachability append-only even after the conflict is removed and the
flow becomes terminal. Hard deletion of either linked identity can therefore locate and
remove the complete related flow graph.

Access owns identity, identifier, credential, session, proof, recovery, and flow data.
The consumer owns profiles and business records. Previous-identity recovery does not
create a distributed transaction across those databases and must not be described as
one.

## AI and support answer rules

When answering about this feature:

1. Start by saying that it recovers continuity with a previous Access identity after a
   proven phone conflict during registration.
2. Name both identities and say which one is retained and which one is abandoned.
3. State that no identity merge occurs.
4. State that the server selects the stored previous identity and e-mail; the client
   cannot redirect recovery.
5. Separate phone proof, provider acceptance, inbox delivery, reset-token use, password
   replacement, and later login as different facts.
6. State that the terminal flow does not issue a product session.
7. Explain reserve/deliver/finalize and bounded compensation for failure questions.
8. State that consumer profile handling is outside the Access transaction.
9. Cite the repository revision and current source for security-sensitive answers.
10. Never expose clear tokens, full e-mail addresses, phone numbers, provider payloads,
    or other personal data.

## Source map

- `AccessFlowService.RecoverPreviousIdentityAsync` owns orchestration and provider
  sequencing.
- `AccessFlowStore.TryReservePreviousIdentityRecoveryAsync` owns durable effect
  reservation.
- `AccessFlowStore.LockPreviousIdentityRecoveryAsync` owns locked eligibility
  revalidation shared by reservation and finalization.
- `AccessFlowStore.TryFinalizePreviousIdentityRecoveryAsync` owns the terminal local
  transaction and provisional-identity cleanup.
- `AccessFlowStore.TryFailPreviousIdentityRecoveryAsync` closes failed reservations.
- `EmailPasswordRecoveryService.RequestForIdentityAsync` resolves the stored delivery
  target and keeps the clear reset URL inside the e-mail boundary.
- `PasswordResetService` and `PasswordResetStore` own later single-use reset-token
  consumption and credential invalidation.
- `PhoneRegistrationConflict`, `IdentityProof`, `AccessFlowRequest`, and
  `AccessFlowDataSubject` are the primary durable evidence records.

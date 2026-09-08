# Baseline AI evaluation set

Use these questions to detect grounding failures after documentation, model, or
retrieval changes. Each case defines facts that must appear and claims that must
not appear. Expected wording may vary.

## 1. Can my React Native app call Bullgate Access directly?

Required facts:

- the app calls its consumer backend/BFF;
- the BFF holds the integration credential;
- opaque session and flow authority remain server-side.

Prohibited claims:

- embedding the integration credential in the app is acceptable;
- an application-client key authenticates the app to Access.

## 2. Are `Identity.Id` and my product's user id the same?

Required facts:

- they are independent identifiers;
- the consumer stores a unique association;
- Access owns identity while the consumer owns its profile.

Prohibited claim: equal GUID values are required.

## 3. Can a registration session authorize product endpoints?

Required facts:

- no;
- it exists to complete registration;
- only a product session is eligible for local-principal resolution.

## 4. Is `applicationClientKey` a secret?

Required facts:

- it is public and stable inside an environment;
- it selects public client metadata;
- it grants no permission.

Prohibited claim: it can replace an integration credential.

## 5. What makes an AccessFlow request idempotent?

Required facts:

- integration-client scope;
- caller `requestId`;
- payload hash;
- stored result/snapshot.

Prohibited claim: a repeated id with different input is accepted.

## 6. Does Twilio decide whether an AccessFlow OTP is valid?

Required facts:

- Access generates the custom code and stores its hash;
- Twilio delivers it;
- local hash comparison decides confirmation.

## 7. Does a phone conflict merge two identities?

Required facts:

- no silent merge occurs;
- the current implementation may change the phone, transfer only the proven
  phone, or request previous-identity recovery when the intent allows it.

## 8. Is account deletion atomic across Access and my product database?

Required facts:

- Access deletion is atomic only inside its PostgreSQL transaction;
- the consumer owns its separate deletion and failure policy;
- no distributed transaction is promised.

## 9. Does deleting an identity wait for Twilio or SMTP?

Required facts:

- provider availability does not condition hard deletion;
- related Access flows are found through `AccessFlowDataSubject`.

## 10. Is Bullgate Access production-hosted today?

Required facts:

- local container and laboratory integration exist;
- public image, production URL, database, secrets, and deployment remain
  unprovisioned according to the current status document.

Prohibited claim: laboratory validation proves a public production deployment.

## 11. Where is the Bullgate admin API?

Required facts: Access implements a separate `/admin/v1` backend for bounded
identity reads, all-current-session revocation, Access-local erasure and complete
configuration replacement. It requires the dedicated Admin service credential
and exact trusted human/function context, not a consumer Bearer. See
[administration](../administration.md). The real Bullgate Admin caller, profile
integration and screens remain Iteration 009; Access owns no operator profile
database and this backend is not an available Admin module or production claim.

## 12. How should a chatbot resolve disagreement between docs and code?

Required facts:

- prefer current executable source for behavior;
- use OpenAPI from the same revision for transport schemas;
- report the mismatch rather than silently merging claims;
- retain the repository revision in evidence.

## 13. Does finding a phone-recovery candidate authorize the recovery?

Required facts:

- no; candidate discovery is a preliminary anti-enumeration lookup;
- the store revalidates identity state, environment policy, and verified phone
  ownership under the identity lock;
- a stale or ineligible candidate does not create password-reset authority.

Prohibited claim: a matching normalized phone alone proves recovery eligibility.

## 14. Is `PasswordRecoveryEmailDelivery` safe to log?

Required facts:

- no; its reset URL contains clear bearer authority;
- only the reset-token hash is safe to persist in Access;
- the clear URL must remain inside the intended recovery delivery channel.

Prohibited claim: a DTO is non-secret merely because it belongs to an e-mail adapter.

## 15. Does changing an identity e-mail preserve verification or old recovery paths?

Required facts:

- no; verification evidence belongs to the previous e-mail value;
- the replacement e-mail starts without verification evidence;
- active reset tokens are consumed and open phone recovery challenges are
  superseded in the same Access transaction.

Prohibited claim: an earlier verified e-mail makes the replacement e-mail verified.

## 16. Does `identity-not-found` prove that an identity UUID does not exist?

Required facts:

- no; the read contract deliberately collapses several absence states;
- the identity may be absent, inactive, outside the authenticated realm, or lack
  the requested identifier;
- a caller-controlled route UUID never broadens integration-client scope.

Prohibited claim: a 404 authorizes searching the same UUID in another realm.

## 17. Can provider-delivery records be written to structured logs?

Required facts:

- no; they may contain a phone/e-mail destination, clear OTP, reset URL, or
  provider credential;
- internal visibility or a DTO/record type does not make the values non-secret;
- logs may use an opaque provider reference and structured outcome code instead.

Prohibited claim: logging the complete object is safe when the log sink is private.

## 18. What happens to sessions and reset tokens after a password change?

Required facts:

- the product session authorizing the change remains active;
- every other active identity session is revoked;
- outstanding password-reset tokens are consumed in the same transaction;
- existing social authenticators remain linked.

Prohibited claim: changing the password signs out the current request before it returns.

## 19. What happens when a social provider is linked more than once?

Required facts:

- the same provider and same subject is idempotent and may refresh provider
  e-mail metadata;
- the same provider with a different subject is rejected;
- a subject owned by another identity is rejected rather than transferred;
- unlink is rejected when it would remove the final authenticator.

Prohibited claim: matching provider e-mail permits identities to be merged.

## 20. Does a failed AccessFlow proof delivery consume the challenge quota?

Required facts:

- no; `DeliveryFailed` challenges remain durable but are excluded from the
  AccessFlow recent-challenge count;
- the person received no usable proof attempt;
- this rule is specific to AccessFlow and must not be generalized to a separate
  password-recovery store without checking its code.

Prohibited claim: all verification and recovery rate limits count failures identically.

## 21. Is an existing AccessFlow OTP invalidated as soon as resend is reserved?

Required facts:

- no; the replacement starts in `PendingDelivery` while an older active challenge
  may remain usable;
- older active challenges are superseded only after replacement delivery
  successfully finalizes;
- if delivery fails, only the new challenge and its request are closed.

Prohibited claim: reserving a resend proves that the new message was delivered.

## 22. Why does AccessFlow put a locally valid phone challenge in `Confirming`?

Required facts:

- Access already compared the OTP with its local stored hash;
- `Confirming` reserves that challenge for one finalizer while ownership and the
  terminal transaction are revalidated;
- Twilio delivery status is not a second proof authority for AccessFlow;
- failed final persistence releases a still-valid reservation for retry.

Prohibited claim: `Confirming` means Access is waiting for Twilio to decide whether the OTP is valid.

## 23. Does entering the previous owner's e-mail prove control of that mailbox?

Required facts:

- no; the current transfer action performs an exact normalized knowledge check;
- no verification code or link is sent to the previous e-mail for this action;
- phone possession was proven separately by the current AccessFlow;
- failed e-mail matches consume a limited, concurrency-protected attempt budget.

Prohibited claim: the previous e-mail is possession-verified during phone transfer.

## 24. Is `recoverPreviousIdentity` one atomic database-and-e-mail operation?

Required facts:

- no; Access first persists an idempotent external-operation reservation;
- recovery targets the stored previous identity by id rather than a client-provided
  delivery address;
- after provider acceptance, finalization revalidates the conflict, identities,
  phone ownership, and phone proof before abandoning the provisional identity;
- later failures close the reservation and, when a token id was returned, make a
  bounded best-effort attempt to consume that reset token;
- provider acceptance does not prove inbox delivery.

Prohibited claim: the database transaction can roll back a recovery e-mail already
accepted by the provider.

## 25. What happens to session authority when an AccessFlow completes normally?

Required facts:

- the terminal snapshot, committed request, new product-session hash, and source
  session revocation are one database transaction;
- registration completion also revokes other registration sessions for the same
  identity and environment;
- phone management rotates only the product session that authorized that flow and
  does not globally revoke other product sessions;
- deterministic issuance allows exact replay without persisting the clear bearer.

Prohibited claim: successful phone management signs the identity out of every other
product session.

## 26. May a client call `skipRegistration` whenever it sees a phone step?

Required facts:

- no; the current persisted snapshot must contain the exact action id and type;
- the server offers skip only for `continueRegistration` when phone collection is
  optional under the environment policy;
- stale, fabricated, or type-substituted actions are rejected;
- `managePhone` never receives a skip action.

Prohibited claim: the step name by itself authorizes skipping registration.

## 27. Does expiring an AccessFlow revoke its source session or undo sent messages?

Required facts:

- no; expiration terminates the flow at an exact expected revision;
- it closes pending local external-operation requests and challenge states in the
  same database transaction as the expired snapshot;
- it does not retract an e-mail or message already accepted by a provider;
- it does not revoke the source identity session, which may start a replacement
  flow if it remains active;
- if another transition wins the revision race, the caller returns the durable
  current snapshot rather than claiming its own expiration succeeded.

Prohibited claim: reaching `expiresAt` automatically rolls back every external effect
and invalidates the login session that started the flow.

## 28. What happens when `StartAsync` finds an active flow for the same session and intent?

Required facts:

- preliminary candidate and active-flow reads are advisory; the store revalidates
  identity and source authority under locks;
- the active flow is resumed only when identity, realm, environment, protocol,
  registration context, integration client, and public application client match;
- resume records the new start request at the existing current revision and returns
  the persisted snapshot without rebuilding it from current policy;
- an incompatible binding is rejected rather than transferred;
- a partial unique index arbitrates parallel creators, and the service performs a
  bounded refresh loop when another creator wins.

Prohibited claim: every valid start request creates a new independent flow.

## 29. Can a client use a new `requestId` to bypass a pending SMS or e-mail operation?

Required facts:

- no; one live pending external request owns the provider effect for the flow;
- only the exact request's finalizer may continue that pending reservation;
- a different action is blocked while ownership remains live, and replaying a
  pending or failed request does not perform delivery again;
- challenge-backed ownership follows the challenge lifetime;
- previous-identity e-mail recovery has no challenge row and uses a one-minute
  request-only grace window;
- after the applicable lifetime, locked reconciliation fails the orphaned local
  request and challenge state before allowing another transition.

Prohibited claim: changing only `requestId` is sufficient authorization to resend an
in-flight provider message.

## 30. Does exact replay return the flow's latest snapshot and a newly trusted session?

Required facts:

- no; a committed request references the immutable result revision it originally
  produced, even if the flow later advanced;
- success is reconstructed from the durable winning request rather than the current
  in-memory command;
- when that request issued a session, Access deterministically derives the same clear
  token from committed scope;
- the derived token hash must match the stored session hash in constant time before
  clear authority is returned;
- PostgreSQL never stores the clear terminal token.

Prohibited claim: replay may return the current flow revision or trust any token that
can be derived from the installation key without checking the committed session hash.

## 31. Can application JavaScript use `flowId` to read or act on a flow directly?

Required facts:

- no; `flowId` and `applicationClientKey` are selectors, not authorization;
- the consumer BFF authenticates as an integration client and supplies exactly one
  capability bound to the flow, integration client, and app environment;
- missing, malformed, repeated, incorrectly scoped, and non-matching capabilities
  collapse to `flow-not-found` rather than revealing which condition failed;
- the BFF retains the capability and any issued session bearer;
- application JavaScript receives the semantic snapshot or a product-specific
  projection, not the complete server transport response.

Prohibited claim: knowing a flow UUID or public application-client key is sufficient
to call AccessFlow endpoints.

## 32. Does successful phone normalization prove that a number exists or is controlled?

Required facts:

- no; normalization is only a canonical syntax check;
- the current shape is `+`, a non-zero first digit, and 8–15 ASCII digits total;
- only outer whitespace is trimmed; country inference, punctuation removal, and
  number-allocation lookup are not performed;
- provider acceptance does not prove handset receipt;
- when policy enables verification, phone possession is established separately by
  the proof journey.

Prohibited claim: an accepted normalized phone is automatically reachable, verified,
or owned by the submitting identity.

## 33. Is a valid integration credential with no permissions an authentication failure?

Required facts:

- no; a valid active credential may authenticate with an empty permission set;
- protected endpoint policies then reject missing grants with HTTP 403;
- malformed or incorrect secrets, expiry, revocation, disabled topology ancestors,
  and unknown stored permission names fail authentication entirely;
- those invalid-credential conditions share the same minimal HTTP 401 Bearer challenge;
- topology and permission claims come only from the authenticated database candidate,
  never route, query, or request-body values.

Prohibited claim: every access denial is HTTP 401 or a request may supply additional
scope and permission claims.

## 34. Does a `bgic_...` integration credential contain trusted scope or permission claims?

Required facts:

- no; it contains only a canonical UUIDv7 lookup id and a 32-byte random secret;
- the UUID is public selection data and does not authenticate by itself;
- workspace, app, environment, realm, client, and permissions are loaded from active
  persistent topology only after the secret hash matches;
- parsing requires the fixed prefix, lower-case UUIDv7 `D` form, separator, exact
  unpadded Base64url length and alphabet, and canonical final character;
- Access stores only the 32-byte `sha256-v1` hash and clears temporary raw-secret
  buffers after use.

Prohibited claim: decoding or editing the token can select a different realm or grant
additional permissions.

## 35. Must every integration secret be revoked when a workspace or realm is disabled?

Required facts:

- no; effective credential activity is computed across integration client,
  environment, app, realm, and workspace;
- any inactive ancestor makes authentication fail for all descendant credentials;
- this does not rewrite secret hashes or set credential revocation metadata;
- expiry and explicit revocation remain independent credential-lifecycle checks;
- both current topology activity and the individual secret lifecycle must pass.

Prohibited claim: disabling a topology ancestor permanently mutates or deletes all
credential records below it.

## 36. Does successful password login always issue a product session?

Required facts:

- no; password possession authenticates the identity but does not complete registration;
- the service checks for an open registration context in the target environment;
- an open context yields a registration-purpose session;
- a registration session may continue registration but cannot authenticate product
  endpoints;
- only a closed or absent context yields product-purpose authority.

Prohibited claim: logging in again is a supported way to bypass unfinished registration.

## 37. Does optional phone policy make a new registration complete immediately?

Required facts:

- not when phone collection is enabled;
- optional means the person may explicitly choose the server-advertised skip action;
- the initial session remains registration-purpose until phone is collected or skip is
  committed by the AccessFlow;
- immediate product authority is issued only when no configured registration journey
  remains.

Prohibited claim: the BFF may infer optionality and promote the registration session
without executing the server-owned flow.

## 38. Do session introspection and revocation reveal whether a bearer exists?

Required facts:

- after integration-client authentication and permission checks, introspection returns
  HTTP 200 for malformed, unknown, expired, revoked, or otherwise inactive bearers;
- every inactive introspection result has `active: false` and omits identity fields;
- revocation returns HTTP 204 for malformed, absent, already-revoked, and matching
  bearers, so it is safe to retry;
- a repeated revocation does not replace the first revocation timestamp;
- these uniform token outcomes do not replace HTTP 401 for an invalid integration
  credential or HTTP 403 for a missing integration permission.

Prohibited claim: `active: false` means the HTTP integration caller was authenticated
as the identity named by the submitted session token.

## 39. Does social sign-in reuse an identity that has the same e-mail?

Required facts:

- no; realm, provider, and provider subject select social credential ownership;
- provider e-mail is contact metadata and may change;
- an unknown provider subject starts a new registration attempt;
- if the asserted primary e-mail is already owned, registration returns a conflict
  instead of merging or reusing that identity;
- concurrent e-mail or subject ownership is decided by database uniqueness at commit.

Prohibited claim: a verified provider e-mail authorizes merging two identity histories.

## 40. Why do social authentication and social linking use different feature gates?

Required facts:

- social authentication may create a new identity and primary e-mail identifier, so it
  requires both e-mail identity and the selected provider to be enabled;
- social linking starts from an active product session for an existing identity;
- linking does not replace or select the identity's primary e-mail;
- the asserted e-mail attached during linking remains provider credential metadata;
- linking therefore requires the provider feature but not the e-mail-registration gate.

Prohibited claim: linking a provider silently changes the identity's primary e-mail.

## 41. Do Google and Apple use the same e-mail-verification claim contract?

Required facts:

- no; both validators bind the assertion to the provider client id protected in the
  target environment and require non-empty subject and e-mail values;
- Google ID-token and access-token validation explicitly require verified e-mail;
- Apple validation requires trusted OIDC signature, Apple issuer, lifetime, environment
  audience, subject, and e-mail;
- the current Apple validator does not separately inspect an `email_verified` claim;
- after either provider-specific contract succeeds, social registration records the
  accepted e-mail as a verified primary identifier;
- identity ownership still comes from provider plus subject, not e-mail.

Prohibited claim: the current Apple validator explicitly checks `email_verified` in the
same way as the Google validators.

## 42. Why is the final-authenticator check inside the social unlink transaction?

Required facts:

- the invariant is that an active identity retains at least one password or social
  authenticator;
- a service-side count can become stale before deletion commits;
- the store locks the identity and evaluates password plus social credentials inside
  the transaction;
- this prevents two concurrent unlink operations from each observing the other
  credential and together removing both;
- provider-not-linked and last-authenticator outcomes leave credentials unchanged.

Prohibited claim: hiding the unlink button in the user interface is sufficient to
enforce the final-authenticator invariant.

## 43. Does an SMTP failure mean no password-reset token was created?

Required facts:

- no; Access persists the token hash before attempting SMTP submission;
- SMTP cannot participate in the PostgreSQL transaction and provider acceptance is not
  proof of inbox delivery;
- a failed or canceled provider operation cannot by itself roll back the durable token;
- trusted orchestration may receive the token id, never the clear bearer, for bounded
  invalidation when a larger operation fails;
- the public recovery endpoint exposes neither that id nor the internal outcome and
  returns HTTP 202 to preserve anti-enumeration;
- an unsuccessful delivery may still consume issuance quota until invalidation or expiry.

Prohibited claim: retrying with a new request is always free because failed SMTP never
counts toward the per-identity issuance limit.

## 44. What credential paths remain after a successful password reset?

Required facts:

- the presented reset token is consumed;
- every other active reset token for the identity is consumed in the same transaction;
- every active identity session is revoked, with no current session preserved;
- existing social authenticators remain linked;
- the preliminary active-token query is not authority because another request may win
  consumption before the transactional locks are acquired;
- a lost race returns the same invalid-token outcome as other ineligible token states.

Prohibited claim: password reset behaves like authenticated password change by keeping
one authorizing product session active.

## 45. Does phone recovery hide every failure behind an accepted response?

Required facts:

- no; unknown phone ownership, hourly rate limit, and resend cooldown share the same
  accepted expiry and resend timing envelope;
- those states are collapsed because exposing them would reveal ownership or recovery
  history;
- malformed or missing phone, invalid application-client key, disabled recovery policy,
  and provider unavailability remain explicit errors;
- the application-client key selects public delivery metadata and does not authorize
  recovery;
- a successful initiation response does not prove that the phone belongs to an identity
  or that a challenge was reserved or delivered.

Prohibited claim: accepted phone-recovery timing proves that Access sent an SMS to a
known identity.

## 46. When does a phone recovery challenge become usable and complete?

Required facts:

- `PendingDelivery` is only a durable reservation and cannot accept code confirmation;
- `Active` begins only after delivery state is attached to the challenge;
- a locally matched code moves to `Confirming`, reserving one provider finalizer;
- provider approval occurs outside the database transaction;
- `Completed`, provider approval, and the new reset-token hash commit together;
- failed replacement rollback may restore only an unexpired provider-backed predecessor.

Prohibited claim: reserving a challenge, sending an SMS, or matching the local code by
itself proves that password-reset authority was issued.

## 47. Do delivery-failed phone recovery challenges consume rate limit and cooldown?

Required facts:

- yes; the hourly count includes every durable phone-recovery challenge for the identity
  across environments in the window, including terminal states;
- resend cooldown follows the identity's latest durable request across environments,
  not only an active challenge in the current environment;
- delivery failure, exhaustion, or supersession does not erase abuse-control history;
- the reservation decision occurs while the identity is locked;
- this is intentionally different from AccessFlow proof counting, which excludes its
  delivery-failed challenges.

Prohibited claim: all Bullgate Access verification and recovery journeys count failed
provider deliveries with the same policy.

## 48. Does Twilio decide whether a phone recovery code is correct?

Required facts:

- no; Access generates the custom code and persists only its hash;
- the store compares the submitted hash in constant time under identity and challenge
  locks;
- a valid local match moves the challenge to the exclusive `Confirming` state before
  provider work begins;
- Twilio approval synchronizes the external verification lifecycle after local proof;
- provider approval is not a second code-validity decision;
- wrong, exhausted, inactive, and ownership-invalidated states are collapsed locally to
  `invalid-code`.

Prohibited claim: Access sends the submitted code to Twilio and trusts Twilio's answer
as the password-recovery proof decision.

## 49. What does the constrained password-reset issuance limit count?

Required facts:

- it counts every durable password-reset token created for the identity since the
  inclusive window boundary;
- the count crosses app environments and recovery channels;
- used, invalidated, and still-active tokens all remain part of issuance history;
- the candidate e-mail lookup is preliminary;
- issuance locks the identity and revalidates lifecycle, environment eligibility, and
  exact expected e-mail ownership before inserting a new token hash;
- the limit measures created reset authority, not successful e-mail delivery.

Prohibited claim: invalidating or consuming a reset token immediately restores issuance
quota inside the same counting window.

## 50. Does submitting the current e-mail again invalidate verification and recovery?

Required facts:

- no; the submitted value is normalized first;
- an exact canonical match is an idempotent success that returns the current snapshot
  without a database mutation;
- existing e-mail verification and recovery state therefore remain unchanged for the
  no-op;
- only an actual replacement clears e-mail verification metadata;
- that replacement also consumes active reset tokens and supersedes open phone-recovery
  challenges in the same transaction;
- database uniqueness remains authoritative if another identity claims the new value.

Prohibited claim: every successful `PUT /v1/account/email` necessarily changes stored
state or invalidates recovery artifacts.

## 51. Does `verifiedAt: null` mean the phone endpoint should return 404?

Required facts:

- no; phone existence and phone-possession proof are separate facts;
- a stored canonical phone returns HTTP 200 even when `verifiedAt` is null;
- null verification time means Access has no recorded possession proof for that value;
- absent identity, inactive identity, cross-realm selection, and missing phone identifier
  share HTTP 404 with `identity-not-found`;
- the route identity UUID is only a selector and never broadens the integration realm.

Prohibited claim: any stored phone is automatically verified or an unverified phone is
indistinguishable from a missing phone identifier.

## 52. Is an abandoned identity the result of user-requested account deletion?

Required facts:

- no; `Abandoned` closes only the provisional identity left by recovery of a previous
  identity;
- the provisional identity row remains as lifecycle history and cannot authenticate;
- the recovery transaction revokes or removes its usable sessions, credentials,
  identifiers, recovery artifacts, and current-flow proof state;
- user-requested deletion is a separate hard delete of attributable Access data;
- neither operation makes deletion of a consumer profile part of the Access transaction.

Prohibited claim: abandonment is soft deletion offered as the account-erasure API or
`DELETE /v1/account` merely changes the lifecycle state to `Abandoned`.

## 53. Does `PasswordCredential.Replace` verify the previous password or reset token?

Required facts:

- no; the entity receives only an already encoded replacement hash;
- the application use case must establish rotation authority first, using the contract
  appropriate to password change or password recovery;
- `IPasswordHashService` owns hash creation, verification, and encoded format;
- `PasswordCredential` owns persisted value shape and creation/replacement timestamps;
- a login verification result that recommends rehashing does not currently cause a
  silent credential rewrite.

Prohibited claim: calling the domain replacement method by itself authenticates a user,
verifies a clear password, or consumes reset authority.

## 54. Can a closed registration context be reopened or given a different outcome?

Required facts:

- no; `Open` may transition only to `Completed` or `Abandoned`;
- repeating the same terminal outcome is idempotent and preserves the original
  `ClosedAt` value;
- attempting to replace one terminal outcome with the other is rejected;
- a registration context is environment-specific progress state, not a session bearer
  and not an AccessFlow capability;
- continuing registration still requires an active registration-purpose session, an
  open matching context, authenticated integration scope, and flow authority.

Prohibited claim: a context id alone authorizes registration, or a retry may reopen or
restamp a closed context.

## 55. Does `active: true` from session introspection always authorize product access?

Required facts:

- no; active session validity and session purpose are separate decisions;
- active requires a scoped session row for an active identity, no revocation, and an
  expiry strictly later than the current UTC time;
- a registration-purpose session may be active but only continue registration;
- only an active product-purpose session may be resolved by the BFF into a product
  principal;
- `sessionId` is a durable selector and never substitutes for the opaque bearer.

Prohibited claim: any introspection response with `active: true` may authenticate
consumer product endpoints regardless of `purpose`.

## 56. Does revoking a session ignore it once it has expired?

Required facts:

- no; expiry is not part of the revocation update predicate;
- an expired matching row may still receive its first explicit revocation timestamp;
- malformed, absent, and already-revoked bearers are successful no-ops;
- repeating revocation preserves the first revocation timestamp;
- HTTP 204 does not reveal which of those states occurred.

Prohibited claim: HTTP 204 proves that an active session existed or that an expired row
cannot be explicitly revoked.

## 57. Does `PasswordResetToken.UsedAt` prove that the password was changed?

Required facts:

- no; the field is the shared terminal marker for reset consumption and compensating
  invalidation;
- either outcome makes the bearer unusable but only the atomic reset transaction
  replaces the password;
- direct domain consumption is strict and rejects an already-used or expired token;
- store-level invalidation is retry-safe because it conditionally updates only an
  unused token strictly before expiry;
- compensating invalidation cannot retract an e-mail already accepted by its provider.

Prohibited claim: every populated `UsedAt` records a successful password replacement,
or a successful invalidation proves that provider delivery was rolled back.

## 58. When may Access advertise `recoverPreviousIdentity`?

Required facts:

- only for a `continueRegistration` flow at the `resolvePhoneConflict` step;
- the provisional flow must have proven possession of the exact verified phone already
  owned by another active identity in the same realm;
- the registration session, context, integration scope, flow capability, revision,
  conflict lifetime, ownership, and durable proof must remain eligible;
- the action must be present in the latest snapshot;
- exhausted previous-e-mail transfer attempts do not remove recovery because recovery
  accepts no caller-selected destination and still requires mailbox possession;
- `managePhone` does not advertise this action.

Prohibited claim: matching phone text, a flow id, or a product-session phone conflict is
enough to manufacture previous-identity recovery.

## 59. Does previous-identity recovery merge the two Access identities?

Required facts:

- no identity merge occurs;
- the previous identity remains active and retains the verified phone;
- the provisional registration identity becomes `Abandoned` after successful
  finalization;
- its registration context is abandoned and its usable authentication, identifier,
  and recovery paths are removed;
- consumer profiles and business data are outside the Access transaction.

Prohibited claim: the feature combines credentials, sessions, identifiers, purchases,
or consumer-profile history into one record.

## 60. Can the client select the previous identity or recovery e-mail?

Required facts:

- no; the action has no client-controlled recovery destination;
- the durable phone conflict fixes the expected previous identity and phone identifier;
- trusted orchestration loads the previous identity's current canonical e-mail inside
  authenticated realm and environment scope;
- a masked e-mail hint is presentation data, not authority;
- the clear reset URL remains inside the e-mail provider boundary.

Prohibited claim: the application may submit an e-mail, identity UUID, or masked hint
to redirect the recovery message.

## 61. Does the terminal `previousIdentityRecoveryRequested` result mean recovery and login completed?

Required facts:

- no; it means local AccessFlow finalization committed after the e-mail provider
  accepted the message operation;
- provider acceptance does not prove inbox delivery or reset-link use;
- the terminal result identifies the retained previous identity and abandoned
  provisional identity;
- this terminal transition issues no product session;
- password replacement, session revocation for the previous identity, and later login
  occur through the separate reset and authentication contracts.

Prohibited claim: the terminal snapshot is a product login, proves delivery, or proves
that the previous identity's password already changed.

## 62. Why does previous-identity recovery reserve before sending e-mail and revalidate after it?

Required facts:

- PostgreSQL and the e-mail provider cannot share an atomic transaction;
- reservation gives one idempotent request ownership of the external effect before
  delivery;
- the reset-token hash is durable before SMTP submission;
- finalization rechecks active identities, conflict, phone ownership, verification,
  current-flow proof, source registration state, revision, and matching request;
- provider acceptance alone cannot authorize abandonment of the provisional identity.

Prohibited claim: the preliminary snapshot or successful SMTP call is sufficient to
commit identity lifecycle changes without locked revalidation.

## 63. What happens if delivery or finalization fails during previous-identity recovery?

Required facts:

- the matching pending request is marked failed when possible;
- when issuance returned a token id, Access makes a bounded best-effort attempt to
  invalidate that exact token without receiving the clear bearer;
- neither compensation retracts an e-mail already accepted by the provider;
- compensation failure can leave the reset link usable until consumption, another
  invalidation, or expiry;
- a disconnect after provider acceptance does not cancel the independent bounded
  finalization attempt;
- the integration treats the outcome as unknown when no durable terminal result can be
  replayed.

Prohibited claim: compensation is distributed rollback, client cancellation proves
failure, or a failed local finalization guarantees the delivered link is unusable.

## 64. What happens after the e-mail-knowledge attempt budget is exhausted?

Required facts:

- the attempt budget protects the e-mail-knowledge check used only by
  `transferPhoneToCurrentIdentity`;
- `transferPhoneToCurrentIdentity` disappears from the advertised snapshot;
- `recoverPreviousIdentity` remains available in `continueRegistration` because it
  sends only to the previous identity's stored canonical e-mail;
- `changePhone` remains available;
- `skipRegistration` also remains available only when phone collection is optional;
- a client must follow the current action list and must not resubmit a hidden action.

Prohibited claim: recovery accepts the guessed e-mail, exhaustion disables every
conflict action, or optional skip is always available.

## 65. Does successful SMS delivery prove phone possession?

Required facts:

- no; provider acceptance and the stored provider reference describe transport;
- only an eligible active challenge may accept code attempts;
- Access compares the submitted code with its locally stored hash;
- durable possession exists only after successful confirmation and `IdentityProof`
  creation commit;
- provider acceptance does not prove handset receipt or code entry.

Prohibited claim: a sent message, provider reference, or HTTP delivery success is an
`IdentityProof`.

## 66. What is the difference between `ProofAttempt` and `IdentityProof`?

Required facts:

- `ProofAttempt` is an immutable record of one committed comparison;
- a failed attempt consumes bounded capacity but grants no authority;
- a successful attempt accompanies final confirmation;
- `IdentityProof` is the durable evidence materialized from that confirmation;
- one challenge may materialize at most one identity proof.

Prohibited claim: every attempt is proof, or a successful attempt row by itself is a
session, identifier transfer, or identity merge.

## 67. Why does a successfully matched code enter `Confirming` before `Verified`?

Required facts:

- the preliminary local hash comparison occurs before final persistence;
- the store must lock and revalidate flow revision, source authority, challenge state,
  expiry, attempts, destination, and phone ownership;
- `Confirming` gives one request exclusive finalization ownership;
- finalization commits the successful attempt, proof, challenge state, and applicable
  identifier, conflict, session, and flow mutations together;
- failed finalization is released only through bounded compensation and replay remains
  authoritative.

Prohibited claim: `Confirming` means proof already committed or permits another caller
to confirm the same challenge concurrently.

## 68. Can the identity that proves a phone differ from the phone's current owner?

Required facts:

- yes, during a phone conflict the provisional flow identity proves current possession;
- `IdentityProof.IdentityId` identifies who performed the proof;
- `SubjectIdentifierId` identifies the exact phone that was proven;
- that identifier may still belong to the previous active identity;
- later server-advertised conflict actions decide whether to transfer the phone, recover
  the previous identity, change the phone, or skip when policy permits.

Prohibited claim: proof automatically transfers ownership, merges the identities, or
lets the client select an unadvertised resolution.

## 69. Why can a failed resend leave an older code active?

Required facts:

- replacement delivery is first stored as `PendingDelivery`;
- the older active challenge is superseded only after replacement delivery and local
  finalization succeed;
- failed replacement delivery closes only the new reservation as `DeliveryFailed`;
- retaining the old challenge avoids a provider failure destroying the person's only
  usable proof path;
- resend cooldown, expiry, current snapshots, and normal attempt limits still apply.

Prohibited claim: reserving a resend immediately invalidates the previous active code,
or a failed provider request creates usable challenge authority.

## 70. Is an AccessFlow `requestId` globally unique or sufficient by itself for replay?

Required facts:

- no; the authenticated integration client is part of the durable idempotency key;
- the same UUID may exist in another integration client's namespace;
- within one namespace, the id is bound to one canonical security-relevant payload
  hash;
- the same hash enables exact replay, while another hash returns
  `request-id-conflict`;
- a request id is not flow capability, session authority, or permission to execute an
  action absent from the current snapshot.

Prohibited claim: request ids are global credentials or may be reused with changed
input because the endpoint path is the same.

## 71. Can a client resolve `revision-conflict` by copying the newest revision number onto its old action?

Required facts:

- no; `expectedRevision` protects the decision represented by one whole snapshot;
- action id, action type, input meaning, feedback, and availability belong to that
  revision;
- the client must fetch the latest snapshot and reconsider only its advertised actions;
- committed exact replay still returns the request's original result revision rather
  than the latest flow snapshot;
- a new decision receives a new request id, while an exact transport retry keeps the
  original id and identical payload.

Prohibited claim: the revision integer is the only stale value or clients may
manufacture an action after refreshing just that number.

## 72. Does `ExternalFailed` prove that an SMS or e-mail provider performed no effect?

Required facts:

- no; it means the request has no committed Access result revision;
- a provider timeout or local finalization failure may occur after external acceptance;
- the state is terminal for that request id so it cannot later acquire a different
  successful history;
- exact replay does not resend and returns delivery unavailable;
- compensation is bounded and cannot make PostgreSQL and the provider one transaction;
- any later operation needs a fresh decision from current durable flow state.

Prohibited claim: `ExternalFailed` proves no message left the provider, permits the
same request to commit later, or authorizes an unconditional retry with a new id.

## 73. What authorizes `DELETE /v1/account`, and can the caller choose an identity id?

Required facts:

- the server-to-server integration credential must authenticate and carry
  `access:identities:manage-current`;
- that credential fixes the only acceptable realm and app environment;
- an opaque active product-session bearer selects the current identity inside that
  scope;
- the request body accepts no identity UUID;
- the store locks and revalidates the session and active identity together before
  deletion;
- a registration session, identity UUID, integration credential, or bearer alone is
  insufficient authority.

Prohibited claim: an integration client may delete any identity in its database by
submitting an id, or a product session may be used across realms or environments.

## 74. Why is `AccessFlowDataSubject` append-only instead of deriving erasure from `AccessFlow.IdentityId`?

Required facts:

- one flow can retain personal data about identities other than its owning identity;
- phone conflicts and previous-identity recovery can describe both a provisional and
  an earlier identity;
- current identifier ownership may change after historical data was captured;
- immutable revision JSON is not a stable relational reachability invariant;
- each described identity receives an explicit indexed link when attribution begins;
- later transfer, resolution, completion, expiry, or cancellation does not remove that
  historical attribution.

Prohibited claim: current flow ownership, current phone ownership, or a text search of
the newest snapshot is sufficient to prove complete erasure reachability.

## 75. If erasing one identity deletes a flow shared with another identity, is the other identity also deleted?

Required facts:

- no; the complete shared flow graph is deleted because it retains the erased person's
  data;
- the other identity row and its directly owned identifiers, credentials, sessions,
  recovery artifacts, and unrelated flows remain;
- deleting the complete graph removes revisions, requests, challenges, attempts,
  proofs, conflicts, and data-subject links belonging to that flow;
- restrictive identity relationships force the flow to be removed before the erased
  identity, rather than cascading deletion into every participant;
- preserving a partial flow history is not preferred over complete erasure.

Prohibited claim: `AccessFlowDataSubject` is a cascade that deletes every linked person,
or a shared flow can keep snapshots about the erased person after only its link is
removed.

## 76. What does HTTP 204 from account deletion prove, and what does a retry with the same bearer return?

Required facts:

- HTTP 204 proves only that the local Access database transaction committed;
- the commit includes attributable flows and the identity-owned graph;
- it does not prove deletion in a consumer database or external provider;
- successful deletion removes every identity session, including the authorizing one;
- a repeated call with the same bearer therefore returns HTTP 401
  `session-inactive`, not another HTTP 204;
- after a lost response, that retry is ambiguous and is not a durable deletion receipt.

Prohibited claim: HTTP 204 is a distributed deletion confirmation, or a later
`session-inactive` response proves that the earlier request definitely committed or
definitely failed.

## 77. Does account deletion contact SMTP, SMS, Twilio, Google, or Apple?

Required facts:

- no provider call is part of the local deletion path;
- provider availability cannot block the Access transaction;
- deleted reset tokens and proof challenges make already delivered local authority
  unusable in Access, but messages cannot be recalled;
- removing a stored social credential does not delete the person's Google or Apple
  account;
- provider-owned logs and retention remain outside the Access database boundary.

Prohibited claim: Access waits for provider confirmation, retracts delivered messages,
or deletes external provider accounts before returning HTTP 204.

## 78. Which records are preserved by current-identity hard deletion?

Required facts:

- Access topology remains: workspace, realm, app, environment, application clients,
  integration clients, integration credentials, and protected policy;
- consumer profile and business data remain unless the consumer separately deletes
  them;
- external provider state remains provider-owned;
- unrelated identities and unrelated flows remain;
- an `Abandoned` identity is a separate retained lifecycle concept and is not the
  result shape of this hard-delete endpoint.

Prohibited claim: account erasure removes the realm or integration credential, performs
a global installation reset, or uses the `Abandoned` lifecycle state as its successful
implementation.

## 79. Does `IsAvailableAsync` prove that SMTP or Twilio is healthy and reachable?

Required facts:

- no; availability means the selected protected environment contains the relevant
  provider configuration;
- the check performs no SMTP connection, Twilio request, destination validation, or
  delivery attempt;
- a true result cannot predict later DNS, network, authentication, quota, template, or
  provider-service success;
- normal durable reservation and failure handling still applies to the later effect;
- a false result describes configuration absence, not identity or destination
  ownership.

Prohibited claim: availability is a provider health check, delivery guarantee, or proof
that a phone number or mailbox exists.

## 80. How do Google ID-token and access-token validation differ?

Required facts:

- ID tokens use Google's signed-token validator with the client id protected in the
  target environment as accepted audience;
- signed-token rejection returns no assertion;
- access tokens are submitted to Google's tokeninfo endpoint;
- tokeninfo must report either `aud` or `azp` equal to the protected client id;
- both paths require non-empty subject, non-empty e-mail, and explicitly verified
  e-mail;
- neither path accepts a request-supplied trusted audience;
- the provider subject, not e-mail, is social credential authority.

Prohibited claim: signature alone is sufficient, a matching e-mail selects an existing
identity, or the mobile application's claimed client id can replace protected server
configuration.

## 81. Can Google UserInfo failure invalidate an otherwise accepted access token?

Required facts:

- no; tokeninfo establishes audience or authorized party, subject, and verified e-mail;
- UserInfo is requested only after those required identity facts pass;
- it supplies optional display-name enrichment only;
- HTTP failure, malformed JSON, or missing name returns an assertion with no display
  name;
- caller cancellation still propagates rather than becoming optional enrichment
  absence;
- the access token remains secret across both provider calls.

Prohibited claim: display name is identity authority, UserInfo must succeed for login,
or the raw access token may be logged because it is also sent to tokeninfo.

## 82. Does Apple validation enforce the same e-mail rule as Google?

Required facts:

- no; Apple validates discovery signing keys, Apple issuer, token lifetime, and the
  environment-owned client id as audience;
- the current normalized assertion requires non-empty `sub` and `email` claims;
- it does not separately inspect an `email_verified` claim;
- it does not infer a display name from ordinary identity-token validation;
- non-cancellation discovery and validation failures collapse to no assertion;
- changing the e-mail claim rule would be a behavioral decision, not a comment-only
  cleanup.

Prohibited claim: current Apple code explicitly requires `email_verified`, uses e-mail
as credential ownership, or exposes signature/discovery failure detail to the client.

## 83. What does Twilio do with an Access-generated phone code?

Required facts:

- Access sends the clear generated code as Twilio Verify `CustomCode` through the
  provider boundary;
- Twilio acceptance returns a `VE` verification reference for correlation and later
  lifecycle updates;
- provider acceptance does not prove handset receipt or phone possession;
- Access compares the submitted code with its local hash before provider approval;
- approval and cancellation update that exact external resource and are not proof
  decisions;
- Android `AppHash` is sent only on the `sms` channel;
- the optional `HJ` password-reset template is used only for password recovery and an
  invalid optional template is ignored.

Prohibited claim: Twilio decides whether the submitted code matches, every journey uses
the recovery template, or a verification SID is durable identity proof.

## 84. Do all provider failures map to the same internal or public result?

Required facts:

- no; each adapter follows its declared application port;
- SMTP configuration absence or caught delivery failure returns `false`, while caller
  cancellation propagates;
- Twilio non-success throws a bounded exception containing HTTP status and a parseable
  provider code while discarding the arbitrary body;
- Google and Apple validation rejection classes produce no social assertion;
- social application endpoints expose stable Access errors rather than raw provider
  diagnostics;
- a timeout or null assertion does not prove that the provider performed no effect or
  that an account does not exist.

Prohibited claim: one generic provider retry rule applies everywhere, or provider body,
exception detail, and Access error code are interchangeable public contracts.

## 85. How does the SMTP adapter protect recovery message content and report failure?

Required facts:

- the target app environment supplies SMTP configuration and the message inputs;
- CR and LF are removed from configured display names before MIME headers are built;
- app name and reset URL are HTML-encoded in the HTML alternative;
- the plain-text alternative necessarily contains the clear reset URL;
- implicit SSL, required STARTTLS, or MailKit `Auto` is selected from mutually exclusive
  configuration flags;
- caller cancellation propagates, while other caught construction or transport failures
  return `false`;
- the failure log deliberately omits the caught provider exception, destination, and
  reset URL because provider diagnostics may contain sensitive information;
- provider submission is not proof of inbox placement or token consumption.

Prohibited claim: HTML encoding removes bearer sensitivity, a `false` result rolls back
the persisted reset token, or sensitive provider diagnostics are safe to log merely
because they originated in an exception.

## 86. Is `Bullgate:MasterKey` a password that Access strengthens for encryption?

Required facts:

- no; it must be valid base64 that decodes to exactly 32 bytes of externally generated
  random key material;
- missing, malformed, shorter, and longer decoded values are rejected;
- Access does not stretch a password or weak operator-selected secret;
- named protocols receive independent 32-byte keys through two HMAC-SHA-256 stages
  under a Bullgate Access domain salt and textual purpose;
- callers clear returned derived-key buffers, and disposal clears the retained decoded
  master-key buffer;
- the configured base64 text and raw master key are not stored in PostgreSQL.

Prohibited claim: Access accepts an arbitrary passphrase, stores the installation key
with the database, or uses the raw master key directly for every protocol.

## 87. Why does the protected environment envelope authenticate its id and format?

Required facts:

- the current format is version 2 and uses AES-256-GCM;
- a fresh 12-byte nonce and 16-byte tag are produced for every write;
- associated data includes the explicit format version and canonical environment UUID;
- associated data is authenticated even though it is not ciphertext;
- moving an envelope to another environment or changing its version therefore fails
  authentication rather than silently changing scope or interpretation;
- strict case-sensitive JSON rejects unknown members after authentication succeeds.

Prohibited claim: changing only the database environment id or version safely reuses
the ciphertext, or JSON parsing establishes cryptographic authenticity.

## 88. Can configuration restoration fall back after a wrong key or damaged envelope?

Required facts:

- no; unsupported version and invalid envelope shape fail before content is interpreted;
- wrong installation key, moved envelope, changed associated data, nonce/tag changes,
  and ciphertext tampering fail GCM authentication;
- authenticated plaintext that violates the strict schema also fails;
- none of these paths returns partial values, maps to ordinary environment absence, or
  accepts global/request-supplied provider settings;
- missing or inactive environment is the distinct case that returns no configuration;
- restoring a database also requires the matching external master key.

Prohibited claim: Access tries alternate keys, ignores unknown fields, or treats every
decryption failure as “provider not configured.”

## 89. What does one successful bootstrap transaction commit together?

Required facts:

- the complete command is validated before the database transaction and writer lock;
- the PostgreSQL `ReadCommitted` transaction obtains one fixed transaction-scoped
  advisory lock for bootstrap writers in that database;
- declared topology, permissions, new credential hashes, application metadata, typed
  policy fields, and protected environment configuration are flushed and committed
  together;
- an uncommitted exception or cancellation rolls back changes from that run and releases
  the transaction-scoped lock;
- validation performs no provider health or credential check;
- the lock does not coordinate independent Access databases.

Prohibited claim: each resource commits independently, manifest acceptance proves live
providers, or the advisory lock is a global cross-database deployment lock.

## 90. Is bootstrap a destructive full desired-state controller?

Required facts:

- no; it processes resources declared in the manifest and leaves omitted resources
  untouched;
- natural keys locate existing resource identity within their documented parent scope;
- workspace, app, and realm names/parents/activity must remain compatible;
- environment policy, recovery URL, and complete protected configuration may update
  while stable environment identity and bindings remain compatible;
- application-client public build metadata may update without changing its stable key,
  id, or environment;
- destructive removal, moves, and reactivation require separate explicit lifecycle work.

Prohibited claim: deleting an item from the manifest deletes it from PostgreSQL, or a
reapply may freely rename and move stable identity boundaries.

## 91. Can a manifest change permissions or recover an existing integration credential?

Required facts:

- no; an existing client's name, activity, environment, and exact ordinal permission
  set must match;
- a permission difference is rejected rather than added or removed;
- bootstrap cannot retrieve the old clear secret because only its hash is stored;
- it also does not rotate or reissue that credential on compatible reapply;
- a newly created client receives a UUIDv7 credential id and 32 random secret bytes;
- only the hash is persisted and the clear `bgic_...` token appears once in the successful
  bootstrap result.

Prohibited claim: bootstrap merges permissions, prints every client's current token, or
a compatible reapply is credential rotation.

## 92. Does a valid public application-client key authorize configuration access?

Required facts:

- no; integration authentication fixes the app environment before public selection;
- the validated stable key selects one application client only inside that environment;
- invalid, unknown, or out-of-environment selection returns no public projection;
- the response includes only versioned common public JSON and selected public client
  metadata;
- provider blocks, development bypass, integration credentials, and master-key material
  are excluded;
- returned JSON elements are cloned into the projection.

Prohibited claim: an application-client key is a bearer credential, selects an arbitrary
tenant, or permits downloading the complete decrypted environment document.

## 93. Why are queryable policy columns stored beside encrypted configuration?

Required facts:

- typed columns let core scoped authorization and policy queries operate without using
  ciphertext as a query model;
- the protected document contains the complete environment-owned policy, providers,
  bypass, public values, and client declarations used by application services;
- bootstrap produces both from one validated environment definition;
- both representations are persisted in the same transaction;
- this duplication does not make the typed columns a substitute source for provider
  secrets or the authenticated document.

Prohibited claim: policy columns expose the full provider configuration, or the two
representations may be updated independently without consistency concerns.

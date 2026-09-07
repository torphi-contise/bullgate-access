# Integration guide

This guide describes the decisions an integrator or coding assistant must make
before writing consumer code. It complements the generated OpenAPI contract.

## 1. Establish ownership

Define the consumer profile type and its unique association to `Identity.Id`.
Do not reuse email or phone as that association. Decide how a product session
resolves or provisions the local profile.

Keep product fields out of Access and identity/contact fields out of the
consumer profile unless the product has an independently justified copy with a
clear synchronization contract.

## 2. Put a BFF in the network path

The application calls the consumer backend. The backend calls Access with a
scoped integration credential. The BFF should:

- store the session token in a host-only, `HttpOnly`, secure cookie;
- store the flow capability server-side, preferably in a path-scoped cookie;
- translate Access failures to stable consumer errors without leaking secrets;
- resolve product sessions into the consumer's local principal;
- preserve registration sessions for the registration journey without
  authenticating product routes.

Access transport responses are not automatically application-safe DTOs. The BFF must
remove `sessionToken`, `flowCapability`, phone-recovery reset authority, and any other
server bearer material before returning semantic state to application JavaScript.
Explicitly public application-client configuration may be projected to the application.
For subsequent flow reads and actions, the BFF submits exactly one capability value;
`flowId` and `applicationClientKey` remain selectors and never replace that authority.

## 3. Bootstrap topology

Create a workspace, app, realm, environment, integration client, and one stable
application client per build family. Grant only the permissions the BFF needs.

Keep the master key, provider secrets, and emitted integration credential in
server secret storage. Application-client keys and explicitly public
configuration may be included in a build.

## 4. Implement session behavior

Registration/login responses may produce registration or product purpose. The
BFF must inspect purpose rather than treating any active token as product auth.
An unavailable Access service is operational failure, not proof that the user
logged out; preserve state for retry unless Access proves the session inactive.

## 5. Implement AccessFlow as a renderer of server state

The UI displays semantic steps and executes only advertised actions. Keep
`requestId`, revision synchronization, single-flight behavior, cooldown, and
capability handling in an SDK/controller layer rather than in individual
screens.

Refresh after revision conflict. Reuse the same request id only for an exact
retry of the same canonical input.

The complete retry contract is in
[`concurrency-and-idempotency.md`](concurrency-and-idempotency.md); public and
internal failure distinctions are in [`failure-model.md`](failure-model.md).

## 6. Handle previous-identity recovery

When a `continueRegistration` flow advertises `recoverPreviousIdentity`, render it as a
route back to an earlier Access identity, not as account merge or immediate login. The
BFF must not accept a recovery identity or destination from the application. Submit the
server-advertised action and treat `previousIdentityRecoveryRequested` as a terminal
request for later password recovery; it does not contain a product session.

Read [`previous-identity-recovery.md`](previous-identity-recovery.md) before implementing
this branch. Consumer-profile association and business-data handling remain a separate
consumer decision after normal authentication succeeds.

## 7. Decide cross-database deletion policy

Access can delete only its identity graph. Call `DELETE /v1/account` only from the BFF,
using an integration credential with `access:identities:manage-current` and the
person's active product-session bearer. Do not accept an identity UUID from application
code as deletion authority.

The consumer must define the order, idempotency, retry, durable intent, and support
behavior for its own data. Do not describe the two databases as one atomic transaction.
HTTP 204 confirms only the Access database commit. A repeated call with the same bearer
after success returns `session-inactive` because deletion removed the authorizing
session; that response alone cannot distinguish a committed first request from another
ineligible-session condition.

Read [`identity-erasure.md`](identity-erasure.md) before implementing this workflow. Do
not introduce consumer-specific schedulers, outboxes, or compensation rules into the
shared Access contract.

## 8. Validate the integration

At minimum, validate:

- wrong, missing, revoked, and under-permissioned integration credentials;
- cross-realm identity lookup rejection;
- registration session rejection on product routes;
- product profile provisioning and repeated resolution;
- exact request replay and request-id payload conflict;
- stale flow revision;
- provider delivery failure after reservation;
- phone conflict actions without identity merge;
- previous-identity recovery without a client-selected destination or premature login;
- Access unavailability without false logout;
- deletion with providers unavailable and no provider calls;
- deletion of a flow linked to two identities while preserving the non-erased identity;
- ambiguous repeated deletion after the authorizing session has been removed;
- absence of secrets in application bundles, logs, and API payloads.

## Using an AI coding assistant

Give the assistant the repository revision and require it to read
`docs/README.md`, `docs/ai/context.md`, the task-specific document, and current
source before proposing code. Ask it to state:

1. the owner of every datum and side effect;
2. the trust boundary crossed by each call;
3. the invariant protected by each non-obvious condition;
4. transactional and external failure behavior;
5. whether the capability is implemented, decided, or proposed;
6. the exact files and contracts it expects to change.

Reject a proposal that invents admin APIs, copies secrets to a client, merges
identities by email, treats registration as product authentication, or promises
cross-database atomicity.

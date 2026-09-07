# Security model

## Trust boundaries

1. The user-facing application is untrusted for server credentials and opaque
   capabilities.
2. The consumer BFF is trusted with its own integration credential and session
   cookies.
3. Bullgate Access authenticates and scopes the BFF before processing identity
   operations.
4. PostgreSQL stores protected configuration and hashes of bearer material.
5. External identity and delivery providers are separate failure domains.

## Secret classes

| Value | May reach application JavaScript? | Persistence |
| --- | --- | --- |
| Integration credential | No | Hash plus lifecycle metadata in Access; raw value only in server secret storage. |
| Session token | No in the recommended BFF design | Hash in Access; raw value in an `HttpOnly` cookie. |
| Flow capability | No | Protected server-side; recommended `HttpOnly` path-scoped cookie. |
| Password reset token | Only through the intended recovery channel | Hash in Access. |
| OTP | Only through the intended delivery channel | Hash in Access. |
| Installation master key | No | External secret storage, never PostgreSQL plaintext. |
| Provider secret | No | Encrypted environment configuration. |
| Application-client key | Yes | Public stable metadata; not authorization. |

## Configuration protection

The installation master key is external 32-byte random material. Access rejects any
other decoded length instead of stretching an operator password. Named cryptographic
uses receive independent HMAC-SHA-256-derived keys; the raw master key is not handed to
callers. Derived buffers are caller-owned and cleared after use, and the decoded master
key buffer is cleared when its holder is disposed.

Environment configuration uses AES-256-GCM with a fresh nonce for every write. The
environment id and envelope format version are authenticated as associated data, so a
valid ciphertext cannot be copied into another environment or relabeled as another
format. Authentication failure, unknown format, and strict-schema failure stop the
read; none may yield partial values or trigger a global/request-supplied fallback.

Queryable policy fields and the protected complete document are persisted in the same
bootstrap transaction. This duplication is deliberate: typed fields support scoped
authorization queries, while the authenticated document is the configuration supplied
to application and provider adapters. Bootstrap is responsible for writing both from
one validated definition so they do not describe different policy revisions.

Public configuration is a projection, not decryption authority. Integration
authentication fixes the environment first; the stable application-client key then
selects only explicitly public common and client metadata in that environment. Provider
secrets, bypass codes, integration credentials, and master-key material are never part
of that projection.

## Isolation

The integration credential fixes workspace, app, environment, and realm.
Identity queries include that scope; accepting a caller-supplied identity id
does not permit a cross-realm read. Identifier and social-subject uniqueness is
enforced inside a realm.

Authentication and authorization remain separate. A valid active credential with
no granted permissions still produces its fixed scoped principal, then permission
policies deny protected endpoints with HTTP 403. Malformed or incorrect secrets,
expired or revoked credentials, disabled topology ancestors, and unknown stored
permission names fail the entire authentication with the same minimal HTTP 401
Bearer challenge.

An integration credential has canonical form
`bgic_<lower-case-uuidv7>.<unpadded-base64url-secret>`. The UUID locates a hash
record and the 32-byte random secret proves possession; the token contains no
topology or permission claims. Parsing rejects alternate UUID, alphabet, padding,
length, and Base64 encodings before database lookup. Access hashes the decoded
secret, clears its temporary byte buffers, and compares only against the stored
32-byte `sha256-v1` value.

Credential lifecycle and topology activity are independent. Authentication derives
effective activity as the conjunction of integration client, environment, app,
realm, and workspace flags. Disabling any ancestor therefore quarantines all
descendant credentials without changing each secret's hash, expiry, or revocation
metadata. A secret must satisfy both its own lifecycle and the current effective
topology state.

## Authentication and sessions

Passwords use the platform password hasher. Opaque session tokens are random
bearer material and only hashes are persisted. Session purpose is part of the
authorization decision: `Registration` cannot be promoted to `Product` by a
consumer merely because the token is active.

Ordinary session and password-reset tokens contain 32 random bytes encoded in one
canonical base64url form. Access validates the form, hashes the complete presented
token with SHA-256, and looks up only the hash. Malformed text does not reach the
database, and the stored hash cannot reconstruct the delivered bearer value.

Flow capabilities and sessions issued by a terminal `AccessFlow` use deterministic,
purpose-separated HMAC-SHA-256 derivation from server-owned UUID scope. This is
intentional: replaying the same committed request must reproduce the same clear token
without storing it. Capability validation compares the complete expected token in
constant time. Terminal replay also compares the newly derived token hash with the
session hash referenced by the committed request before returning clear authority.
The HMAC key is derived for this use from the installation master key and cleared when
the service is disposed.

The ASP.NET Core Identity password hasher owns the encoded password format. A
verification result that requests rehashing still proves the password, but the current
adapter does not silently rewrite credentials during login.

`PasswordCredential` receives only an already encoded hash. It validates persisted
value shape and timestamps but does not authenticate the previous password or consume
reset authority; the application use case must establish that authority before asking
the domain entity to replace the hash.

## External identity validation

Social tokens are validated only on the server against the provider client id stored
in the target environment's protected configuration. A client-supplied audience or
provider configuration value is never accepted.

Google ID tokens use Google's signed-token validator with the configured audience and
must contain a non-empty subject and verified e-mail. Google access tokens use the
provider tokeninfo endpoint; either `aud` or `azp` must match the configured client id,
and the subject and verified e-mail must be present. UserInfo may add a display name,
but failure to retrieve that optional name does not invalidate otherwise accepted
identity claims.

Apple identity tokens are checked against Apple OpenID Connect signing keys, the
`https://appleid.apple.com` issuer, the environment client id as audience, and token
lifetime. The current normalized assertion requires non-empty `sub` and `email` claims
and does not infer a display name or perform a separate `email_verified` claim check.
This differs from Google validation, which explicitly requires verified e-mail. In
both cases, only an accepted provider assertion may create the primary identifier with
verification evidence; the provider subject, not the e-mail, remains credential authority.

Provider subject is the stable social credential key. Provider e-mail is contact
metadata and never authorizes merging with an existing identity.

Provider rejection surfaces are intentionally narrow. Google ID-token validation maps
signed-token rejection to no assertion. Google access-token validation also maps
provider HTTP failure, malformed tokeninfo JSON, and unexpected claim shapes to no
assertion. Apple maps discovery, signing, lifetime, issuer, audience, claim, and other
non-cancellation validation failures to no assertion. Application clients receive the
stable social-authentication error contract, not provider bodies or validation detail.
Caller cancellation remains a control-flow signal where the adapter can observe it.

Google access-token tokeninfo places the opaque bearer in the provider request URI, as
required by that provider contract. HTTP telemetry must redact the URI query with the
same care as an Authorization header. UserInfo reuses the bearer only for optional
display-name enrichment; its failure cannot invalidate subject, audience, and verified
e-mail facts already accepted from tokeninfo.

## Idempotency and concurrency

`requestId` prevents duplicate effects only when paired with a payload hash and
scope. Reusing an id with different input is rejected. Flow revisions prevent a
stale client from applying an action to a newer state.

PostgreSQL constraints and deterministic lock order are part of the security
model. Application-level prechecks are usability optimizations, not substitutes
for transactional arbitration.

## External effects

Email and SMS cannot participate in a PostgreSQL transaction. Operations that
send them reserve durable state before delivery, then finalize or mark failure.
This prevents an untracked message from being treated as if no request existed.

For `AccessFlow` and phone password-recovery confirmation, Access validates the local
OTP hash in constant time. Phone recovery then reserves the challenge for one confirmer
before marking the provider resource approved. That provider update synchronizes
lifecycle after local proof; it does not ask Twilio to decide whether the code is valid.

A delivered challenge, a committed comparison attempt, durable identity proof,
identifier verification metadata, and current identifier ownership are separate
security facts. Successful AccessFlow confirmation materializes them in one locked
transaction where applicable; no earlier provider response or preliminary read may
invent the later facts. See [`proof-lifecycle.md`](proof-lifecycle.md).

Provider adapters load credentials only from the protected configuration of the
target environment. SMTP display names have line breaks removed and dynamic HTML
values are encoded before message construction. Twilio failure handling retains a
structured provider error code when available but does not include an arbitrary
response body in application exceptions. Raw provider credentials, OTPs, reset URLs,
and destination contact values must not be added to logs.

Provider availability methods currently mean only that the selected environment has
the relevant protected configuration. They do not connect to SMTP, Twilio, Google, or
Apple and must not be presented as health or reachability checks.

The SMTP adapter returns `false` for configuration absence or a caught transport or
message-construction failure, while caller cancellation propagates. Its failure log
contains the stable operation category and app name, but deliberately omits the caught
provider exception, destination, and reset URL because external diagnostics may contain
sensitive data.

Twilio non-success responses become an exception containing HTTP status and a
structured provider error code when parseable; the arbitrary body is discarded. A
successful create response must contain a `VE` verification SID, and a lifecycle update
must return the requested status. Those checks prove usable provider correlation, not
handset receipt or identity proof.

## Deletion

Hard deletion is authorized by two independent boundaries: the integration credential
fixes realm, environment, and permission, while an active product-session bearer
selects the identity. The request accepts no identity UUID. The store locks and
revalidates both session and identity before mutating data; a preliminary lookup is not
commit authority.

Deletion finds every flow retaining the identity through append-only
`AccessFlowDataSubject` links, removes each complete flow graph, and then deletes the
identity and its dependent Access data in one Access transaction. A link can cause a
flow owned by another identity to be removed, but it never causes that other identity
to be deleted. Provider availability does not block deletion.

Deletion of consumer product data is a separate transaction owned by the
consumer. Documentation and UI must not promise distributed atomicity or treat HTTP
204 as proof of provider-side deletion. Read
[`identity-erasure.md`](identity-erasure.md) for the full authorization, graph, retry,
and failure contract.

## Logging and observability

Do not log raw credentials, session tokens, capabilities, reset tokens, OTPs,
provider secrets, encrypted plaintext, or unnecessary personal data. Logs may
carry correlation ids, stable error codes, internal ids where operationally
necessary, and redacted provider outcomes.

## Security reports

Do not disclose a suspected vulnerability in a public issue. Follow the private
reporting process in `SECURITY.md`.

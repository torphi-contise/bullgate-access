# Configuration and bootstrap

## Installation values

An Access process needs:

```text
ConnectionStrings__AccessDatabase
Bullgate__MasterKey
```

The master key is exactly 32 random bytes encoded as base64. It protects the
environment configuration and derives purpose-separated keys. All processes
that read or write protected configuration must receive the same installation
key.

The configured value must already contain 256 bits of random key material. Access
rejects missing, malformed, shorter, and longer decoded values; it does not stretch a
password or weak operator-selected secret into a key. The base64 text is decoded once
per key-deriver lifetime, and the retained decoded buffer is cleared when that service
is disposed.

Key derivation uses two HMAC-SHA-256 stages under a Bullgate Access domain salt. Each
caller supplies a stable textual purpose, which is trimmed and prefixed with the
Bullgate Access namespace before derivation. This is purpose separation, not password
stretching and not direct reuse of the master key. The returned 32-byte buffer belongs
to the caller and must be cleared after use.

A derived key for environment configuration must not be reused for sessions, flow
capabilities, or another cryptographic purpose. Replacing the installation key without
first providing an explicit re-encryption path makes existing protected configuration
unreadable. A database backup containing protected envelopes is therefore not
sufficient for recovery unless the matching external master key is also recoverable.

Do not track either value. Do not expose them to a browser or mobile app.

## Manifest version 2

The optional `Bullgate__Admin__CredentialSha256` setting enables only the
separate administrative scheme. It is a 64-hex-character verifier of a random
32-byte Admin service secret, not the master key. See [administration](administration.md)
for trust, configuration-target revisions and complete JSON replacement. This
slice does not provision real credentials or change CLI writer ownership.

The CLI accepts a strict, case-sensitive JSON manifest with
`manifestVersion: 2`. Unknown properties are rejected. One manifest defines:

- workspace, apps, realms, and environments;
- identifier and authenticator access policy;
- verification and recovery limits;
- SMTP, Twilio Verify, Google, and Apple providers;
- explicit development bypass settings;
- versioned public environment configuration;
- integration clients, permissions, and application clients.

The CLI accepts one exact command form and one manifest path. Missing nested values,
null collections, a non-object public-configuration value, unsupported platform text,
and domain-policy violations are rejected before the bootstrap transaction begins.
Platform wire values are the lowercase strings `android`, `ios`, and `web`.

`accessPolicy.identifiers.cpf` controls the linked collection of CPF and birth
date. The block may be omitted by older manifests, which is equivalent to a
disabled policy. When present and enabled, `required` must be `true` and
verification must remain disabled: this flow validates CPF structure and stores
the value, but it does not claim independent CPF ownership proof.

When CPF is enabled, `accessPolicy.cpfCollectionPosition` must explicitly be
`beforePhone` or `afterPhone`; no collection order is selected implicitly.
`afterPhone` requires `identifiers.phone.enabled: true` and
`identifiers.phone.required: true`. The domain policy rejects other combinations,
and PostgreSQL enforces the same after-phone constraint. This ordering rule does
not require phone verification to be enabled. CPF-disabled manifests may omit
the position.

Apply a manifest with:

```powershell
dotnet run --project src/Bullgate.Access.Cli -- bootstrap --manifest <path>
```

Standard output contains exactly one JSON `BootstrapTopologyResult`. When new
integration clients are created, that document contains their one-time clear
credentials and must be captured as secret material rather than ordinary build logs.
Human-readable status and errors use standard error so automation can parse standard
output without mixed log lines.

Exit code `0` means the transaction completed. Exit code `2` means usage, JSON shape,
manifest, or topology validation was rejected. Exit code `1` means an unexpected
bootstrap failure. A nonzero result never proves that no earlier external process
changed the database; diagnose against the database and the exact command invocation.

Use `examples/bootstrap.development.example.json` as an executable provider-free
example. `examples/bootstrap.baybo.development.json` is a placeholder template,
not a deployable production manifest.

## Protected environment configuration

The full environment document is encrypted with AES-256-GCM before it is stored
in PostgreSQL. Nonce, ciphertext, tag, format version, and update time are
persisted. Queryable policy flags are also stored as typed fields so core access
decisions do not require treating an encrypted document as a query model.

The app-environment id and configuration format version are authenticated as
associated data. Therefore, copying an otherwise valid encrypted document to a
different environment, changing its recorded version, using the wrong installation
key, or modifying its bytes causes authentication to fail before deserialization.
The JSON reader also rejects unknown members so a misspelled security property is
not silently ignored.

Provider secrets belong to an environment. There are no global SMTP, Twilio,
Google, Apple, bypass, or journey-limit settings that silently leak between
tenants.

### Envelope contract

The current envelope format is version `2`. It uses:

- a key derived for `app-environment-configuration-v2`;
- a fresh random 12-byte nonce for every write, including an identical reapply;
- AES-GCM ciphertext and a 16-byte authentication tag;
- associated data in the form
  `bullgate-access/app-environment-configuration/2/<environment-guid>`;
- strict camel-case, case-sensitive JSON with string enums and no unknown members.

The database columns hold only the format version, nonce, ciphertext, tag, and update
time. Plain provider credentials are serialized in memory but are never assigned to
entity columns. Temporary derived-key, plaintext, and associated-data buffers are
cleared after protection or restoration.

Restoration rejects an unsupported version or malformed envelope shape before trying
to interpret content. Authentication runs before JSON deserialization. A wrong master
key, moved envelope, changed associated data, modified ciphertext, nonce, or tag all
fail without returning partial configuration. Valid authenticated plaintext that does
not match the strict current schema also fails; the reader does not guess a previous or
future format.

There is currently no automatic key rotation or envelope migration. Operators must
not replace the master key and hope that Access can fall back to another source. Any
future rotation must explicitly authenticate with the old key, protect with the new
key, preserve the environment binding, and provide an operational rollback strategy.

### Protected input and public output

The configuration reader selects only an active environment and loads only its
encryption envelope without tracking the persistence entity. Absence or inactivity
returns no configuration. Authentication, key, format, and JSON failures surface as
configuration failures; they are deliberately not converted to absence because a
fallback could cross environment or trust boundaries.

The public application-client endpoint starts from the environment already fixed by
the authenticated integration credential. It then validates the stable public
`applicationClientKey` and selects a declaration only inside that protected
environment. The key grants no permission and cannot select another environment.

The response contains only the versioned common public JSON and the selected client's
public metadata: key, name, lowercase platform, optional application/signing/SMS hash
values, and client public JSON. Returned JSON elements are copied into the projection.
Provider blocks, development bypass values, integration credentials, and the
installation master key never belong to this response.

## Provider configuration invariants

Provider blocks live only inside the protected environment document. They are never
part of public application-client configuration. A configured block makes an adapter
available for selection; it does not perform a provider health check or prove that a
future request will succeed.

Bootstrap enforces these relationships before the topology transaction begins:

- enabling phone verification requires `providers.twilioVerify`;
- any Twilio Verify block requires the phone identifier feature to be enabled;
- enabling Google authentication requires `providers.google` with a non-empty
  `clientId`;
- enabling Apple authentication requires `providers.apple` with a non-empty
  `clientId`;
- `recoveryPolicy.passwordRecoveryUrl` and `providers.smtp` must either both be
  present or both be absent;
- SMTP requires the e-mail identifier feature, a host, a valid port, a canonical sender
  address, and a non-empty sender display name;
- SMTP user and password must be present together or both absent;
- SMTP cannot request both STARTTLS and implicit SSL.

The SMTP transport uses implicit TLS when `useSsl` is true, required STARTTLS when
`useStartTls` is true, and MailKit `Auto` selection when both are false. Configuration
acceptance is not evidence that a live connection negotiated a particular security
mode. A null SMTP user selects anonymous transport authentication.

Twilio credentials, service id, channel, and locale must be non-empty. The optional
password-reset template is applied only to password-recovery messages and is ignored at
runtime if it is not shaped like a Twilio content-template SID. Android SMS Retriever
`AppHash` is sent only for the `sms` channel.

Google and Apple client ids are trusted server-side audiences. A token or application
request cannot replace them. Google access-token validation accepts a matching `aud` or
`azp`; Apple identity-token validation requires the protected client id as its
audience.

## Integration clients

An integration client represents a trusted backend. Bootstrap issues an opaque
`bgic_...` credential once when a client is created; only a hash is persisted.
Reapplying a compatible manifest does not issue a new credential. Rotation and
revocation are explicit lifecycle operations.

The credential contains a public lookup id and 32 random secret bytes. Access uses
the id to find a candidate, validates the complete active topology and permission
set, hashes the presented secret, and compares the hash in constant time. Disabling
the workspace, app, realm, environment, or integration client invalidates the fixed
scope without moving or reissuing the credential.

In Compose, `BULLGATE_INTEGRATION_CLIENT_PATH` selects the exact client whose
credential is written to the private integration volume. A multi-client
manifest must never rely on "the first credential".

## Application clients

An application client represents a public build identity such as
`android-development`, `ios-development`, or `web-development`. Its key is
stable and public inside an environment. Platform, application id, signing
identity, SMS Retriever app hash, and public configuration are metadata; the
database UUID is internal.

An application-client key is not authentication and grants no permission.

## Idempotent application

Bootstrap runs under a PostgreSQL advisory lock and resolves resources by
natural keys. Only declared resources are processed. A compatible reapply
updates configuration without duplicating topology or credentials.

The transaction-scoped advisory lock is installation-wide. It prevents concurrent
bootstrap processes from both observing an absent natural key and attempting to
create or reconcile the same security topology. The topology, permissions, issued
secret hash, and protected configuration commit together.

Existing resources are resolved by natural key and checked for compatibility. The CLI
does not silently rename, re-scope, or change the permissions of an existing resource
to make a new manifest fit. Newly created integration clients receive credentials;
compatible existing clients do not have their credentials recovered or reissued.

### Transaction pipeline

Bootstrap first validates the complete command in memory. No transaction or advisory
lock is opened until keys, names, references, permissions, policy limits, provider
relationships, client platforms, public JSON shapes, and development-bypass rules are
accepted. This is deterministic contract validation only; it does not contact a
provider or prove credentials are live.

After validation, one UTC timestamp is captured and a PostgreSQL `ReadCommitted`
transaction obtains the fixed transaction-scoped advisory lock. The handler resolves
the graph in parent-before-child order, protects each declared environment's complete
configuration, flushes once, and commits once. Disposing an uncommitted transaction
rolls back every topology, permission, secret-hash, metadata, and configuration change
from that run. PostgreSQL releases the advisory lock with the transaction.

The lock is database-wide for bootstrap writers, not a distributed lock across
different Access databases. Natural-key uniqueness still protects storage integrity;
the lock additionally prevents two processes from interleaving the read-then-create
and compatibility checks.

### Reconciliation rules

Bootstrap is declarative for resources present in the manifest, but it is not a
destructive full desired-state controller. Omitted resources are left untouched.

| Resource | Natural-key scope | Compatible existing behavior | Rejected implicit change |
| --- | --- | --- | --- |
| Workspace | `key` | Reuse id. | Name change or reactivation. |
| App | `workspaceId + key` | Reuse id. | Parent move, name change, or reactivation. |
| Realm | `workspaceId + key` | Reuse identity partition. | Parent move, name change, or reactivation. |
| App environment | `appId + key` | Reuse id; update access policy, password-recovery URL, and full protected configuration. | Workspace/app/realm move, name change, or reactivation. |
| Integration client | `appEnvironmentId + key` | Reuse id when name, activity, and exact permission set match. | Rename, move, reactivation, permission grant, or permission removal. |
| Application client | `appEnvironmentId + key` | Reuse id/key and update public build metadata. | Move to another environment or reactivation. |

Realm keys are unique across the workspace even though the manifest nests realm
declarations under apps. This prevents two app sections from appearing to define
separate identity partitions while resolving to one realm key.

For a new integration client, Access inserts its permissions in ordinal order, creates
a UUIDv7 credential id and 32 random secret bytes, persists only the SHA-256 hash, and
returns the clear `bgic_...` token once. Reapplying the manifest neither reads the old
secret nor rotates it. Permission differences are rejected as a security-sensitive
lifecycle operation, not merged additively.

## Compose initialization order

```text
PostgreSQL healthy
  -> initializer
       -> create or reuse master key
       -> apply schema migration
       -> apply manifest v2
       -> create or reuse selected integration credential
  -> Access API with read-only master-key volume
  -> consumer BFF with read-only integration-credential volume
```

`docker compose down` preserves state. `docker compose down --volumes` destroys
the local database, master key, and issued credential and is an intentional
local reset.

## Production status

The repository contains local Docker assets, not a provisioned production
environment. A production installation still needs an image registry,
PostgreSQL, stable master key, secret store, environment-specific manifest,
network policy, TLS termination, monitoring, backup, and source-availability
plan appropriate to the AGPL.

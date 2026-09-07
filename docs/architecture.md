# Architecture

## System boundary

Bullgate Access is a server-side identity and access service. A consumer
backend authenticates with an integration credential and acts as the only
network bridge between its application and Access.

The service does not render login pages and does not require a hosted UI,
WebView, or remote HTML. Consumer applications own their native or web
experience. Bullgate SDKs translate that experience into BFF calls, while the
BFF translates those calls into authenticated Access API calls.

## Components and dependency direction

```text
Domain <- Application <- Infrastructure
             ^                ^
             |                |
          Api / Cli     Api / Cli / Migrations
```

### Domain

`Bullgate.Access.Domain` contains topology, identities, identifiers, sessions,
credentials, recovery artifacts, proofs, and access-flow entities. Constructors
and state-transition methods enforce local invariants. It has no ASP.NET Core,
Entity Framework Core, PostgreSQL, or provider dependency.

### Application

`Bullgate.Access.Application` contains use cases and ports. Services coordinate
domain objects, stores, token services, provider delivery, and failure mapping.
External effects that cannot share a database transaction use explicit
reserve/perform/finalize or reserve/perform/fail protocols.

### Infrastructure

`Bullgate.Access.Infrastructure` implements the application ports. PostgreSQL
transactions, deterministic lock ordering, unique constraints, cryptographic
protection, SMTP, Twilio Verify, Google, and Apple adapters live here.

### API, CLI, and migrations

`Bullgate.Access.Api` authenticates integration clients, applies permission
policies, maps HTTP contracts, and composes the process. `Bullgate.Access.Cli`
applies declarative topology manifests. `Bullgate.Access.Migrations` owns schema
migration in a separate process so production ordering stays explicit.

## Tenancy topology

```text
Workspace
  App
    AppEnvironment ---- Realm
      IntegrationClient
      ApplicationClient
```

- A `Workspace` groups resources owned by one operator.
- An `App` represents a consumer product.
- A `Realm` is the identity uniqueness boundary.
- An `AppEnvironment` connects an app to a realm and owns policy, providers,
  protected configuration, and public configuration.
- An `IntegrationClient` represents a trusted server and receives explicit
  permissions and rotatable secrets.
- An `ApplicationClient` is a public, stable identity for a client build.

The integration credential determines the environment and realm. Public
application-client keys are resolved only inside that authenticated boundary.
Database UUIDs are internal implementation details.

## Identity and product profiles

An Access `Identity.Id` and a consumer product's profile id are independent.
The consumer stores a unique association to the Access identity. Access owns
contact and authentication data; the consumer owns profile and business data.

There is no distributed transaction between the Access database and a consumer
database. Each consumer decides ordering, retry, compensation, and operational
handling for cross-service operations such as complete account deletion.

## Sessions and long-running journeys

Access issues opaque session tokens and stores only their hashes. Registration
sessions permit completion of registration but do not authenticate a consumer
product principal. Product sessions may be resolved by the BFF into a local
principal.

One-step operations use direct endpoints. Stateful journeys use `AccessFlow`,
which provides a declared intent, protocol version, expiring capability,
optimistic revision, server-declared actions, request-level idempotency, stored
snapshots, and explicit terminal results.

The client may perform only actions returned by the current snapshot. It must
not infer the next step or manufacture an action identifier.

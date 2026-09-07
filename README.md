# Bullgate Access

Bullgate Access is a self-hosted identity and access service for mobile-first
products. It owns identities, identifiers, authenticators, sessions, password
recovery, possession proofs, identity-resolution flows, and application
topology. Consumer products keep ownership of their user interface and business
profiles.

> **Project status:** the current Access baseline is implemented and integrated
> with its first consumer in a development laboratory. It is not yet published
> as a production service, package, or hosted offering. See
> [Project status](docs/project-status.md) before planning a deployment.

## Why Bullgate Access exists

Authentication is only the beginning of an account lifecycle. Real products
also need to preserve a person's continuity when an identifier belongs to an
older account, a phone number changes hands, a registration is interrupted, or
a recovery operation crosses an external provider boundary.

Bullgate Access makes those journeys explicit and auditable. It provides:

- email/password registration and login;
- Google and Apple authentication and account linking;
- opaque, revocable registration and product sessions;
- email and phone password recovery;
- verified phone possession with Android SMS Retriever metadata;
- persistent, versioned `AccessFlow` journeys;
- phone-conflict resolution without silently merging identities;
- recovery of a previous identity after a proven registration phone conflict;
- declarative multi-app, multi-environment, and multi-realm topology;
- protected per-environment provider configuration;
- scoped server-to-server credentials and permissions.

## Ownership boundary

Bullgate Access owns identity, contact identifiers, authenticators, sessions,
recovery, proofs, access flows, and access topology. The consumer product owns
its local profile, business data, screens, copy, navigation, analytics, and
product-specific effects.

The mobile application never receives the integration credential and never
calls Bullgate Access directly. A server-side adapter or BFF calls Access, keeps
opaque tokens in `HttpOnly` cookies, and maps `Identity.Id` to the product's
local profile.

## Architecture

```text
mobile or web application
          |
          | HTTPS to the product backend
          v
consumer backend / BFF
          |
          | scoped integration credential
          v
Bullgate Access API
          |
          v
PostgreSQL
```

The source follows a dependency-inward architecture:

```text
Bullgate.Access.Domain
          ^
          |
Bullgate.Access.Application
       ^             ^
       |             |
     Api / Cli   Infrastructure
                       ^
                       |
                  Migrations
```

| Project | Responsibility |
| --- | --- |
| `Bullgate.Access.Domain` | Entities, lifecycle state, and invariants without framework dependencies. |
| `Bullgate.Access.Application` | Use cases, ports, public contracts, and orchestration. |
| `Bullgate.Access.Infrastructure` | PostgreSQL persistence, cryptography, and external providers. |
| `Bullgate.Access.Api` | HTTP transport, integration-client authentication, and composition root. |
| `Bullgate.Access.Cli` | Explicit topology bootstrap operations. |
| `Bullgate.Access.Migrations` | Separate database migration runner. |

Read [Architecture](docs/architecture.md) and
[Domain model](docs/domain-model.md) for the detailed boundaries. The complete
challenge-to-proof contract is in
[Proof lifecycle](docs/proof-lifecycle.md). The complete
continuity contract for one of Access's central identity-resolution paths is in
[Previous identity recovery](docs/previous-identity-recovery.md). The local account
deletion boundary and historical flow reachability are defined in
[Identity erasure](docs/identity-erasure.md).

## Local development

Requirements:

- .NET SDK 10;
- Docker with Compose support.

Start the local installation:

```powershell
./scripts/run-local.ps1
```

The composition starts PostgreSQL, applies the consolidated schema, bootstraps
the example topology, and then starts the API. The liveness endpoint is
`http://localhost:5227/health/live`. In `Development`, OpenAPI is available at
`http://localhost:5227/openapi/v1.json`.

The initializer creates and preserves two separate private volumes:

- `bullgate-access-master-key`, mounted by Access;
- `bullgate-access-integration`, intended for the consumer BFF.

Do not copy the generated credential into source files, tracked settings, or a
mobile application. See [Configuration and bootstrap](docs/configuration.md).

## HTTP API

Every application endpoint requires a bearer integration credential with the
matching permission. The credential determines the workspace, app,
environment, and realm; callers cannot select another realm in a request.

The implemented surface includes `/v1/auth/*`, `/v1/account/*`,
`/v1/access/flows/*`, `/v1/identities/{identityId}/*`, and
`/v1/config/application-clients/*`. See [HTTP API](docs/http-api.md) for the
route and permission map. Generated OpenAPI is authoritative for transport
schemas; code is authoritative when prose and implementation diverge.

## Documentation

The documentation is intentionally structured for both people and retrieval
systems:

- [Documentation map](docs/README.md) — reading order and trust rules;
- [Architecture](docs/architecture.md) — process and dependency boundaries;
- [Integration guide](docs/integration-guide.md) — safe server/BFF integration sequence;
- [Domain model](docs/domain-model.md) — topology, identity, session, proof, and flow concepts;
- [AccessFlow protocol](docs/access-flow.md) — state, actions, replay, and external effects;
- [Concurrency and idempotency](docs/concurrency-and-idempotency.md) — retries, races, and provider effects;
- [Identity erasure](docs/identity-erasure.md) — deletion authority, data reachability, and ownership boundaries;
- [Failure model](docs/failure-model.md) — error classes, anti-enumeration, and caller behavior;
- [HTTP API](docs/http-api.md) — routes, permissions, and transport rules;
- [Configuration and bootstrap](docs/configuration.md) — manifest and secret model;
- [Security model](docs/security-model.md) — threat boundaries and invariants;
- [Commenting guide](docs/commenting-guide.md) — useful XML and implementation comments;
- [Decision catalog](docs/decision-catalog.md) — the important `if` and `why` contracts;
- [Project status](docs/project-status.md) — implemented, pending, and absent capabilities;
- [AI context](docs/ai/context.md) — compact grounding facts for assistants;
- [AI glossary](docs/ai/glossary.md) — stable meanings and forbidden conflations;
- [AI retrieval guide](docs/ai/retrieval-guide.md) — ingestion, citation, and answer rules;
- [AI evaluation set](docs/ai/evaluation-set.md) — baseline questions and required facts;
- [`llms.txt`](llms.txt) — machine-readable documentation entry point.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before
opening an issue or pull request. Security reports must follow
[SECURITY.md](SECURITY.md), not a public issue. Community participation is
governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

Every contributed commit must comply with the [Developer Certificate of Origin
1.1](DCO). The contribution and hosted-service model is documented in
[open-source governance](docs/open-source-governance.md).

## License

Bullgate Access is licensed under the
[GNU Affero General Public License version 3 or later](LICENSE). If you modify
the service and make it available to users over a network, review section 13 of
the license.

Copyright in the original project is held by Torphi Contise Tratamento de Dados
Ltda. See [COPYRIGHT.md](COPYRIGHT.md) for contribution and third-party ownership
boundaries.

The license does not grant rights to use Bullgate names, trademarks, or visual
identity except as required for reasonable descriptive use.

Bullgate Cloud may provide a paid managed instance of this same open-source
service. Customers pay for hosting and operations; the Bullgate Access product
and accepted external contributions remain AGPL-3.0-or-later.

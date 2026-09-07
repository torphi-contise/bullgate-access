# Contributing to Bullgate Access

Thank you for helping improve Bullgate Access. Contributions may include bug
fixes, tests, provider adapters, documentation, accessibility improvements, and
well-scoped design proposals.

## Before opening a change

- Read the required documents in [`docs/README.md`](docs/README.md).
- Search existing issues and pull requests to avoid duplicate work.
- Open a design discussion before changing an HTTP contract, persisted state,
  tenancy boundary, cryptographic format, identity-ownership rule, or public
  extension point.
- Report vulnerabilities privately according to [`SECURITY.md`](SECURITY.md).

## Development setup

The repository requires .NET SDK 10 and Docker with Compose support.

```powershell
./scripts/run-local.ps1
```

The local API exposes liveness at `http://localhost:5227/health/live` and, in
Development, OpenAPI at `http://localhost:5227/openapi/v1.json`.

Use only non-secret example configuration. Never commit an emitted `bgic_`
credential, master key, session token, OTP, reset token, provider secret, or
personal data.

## Design rules

- Keep the domain independent of ASP.NET Core, Entity Framework Core,
  PostgreSQL, and providers.
- Put orchestration and ports in `Application`; put implementations and
  transaction mechanics in `Infrastructure`.
- Preserve realm and environment isolation in every query and mutation.
- Treat database constraints and lock ordering as part of the contract.
- Model external effects explicitly; do not imply that email, SMS, or provider
  calls share a PostgreSQL transaction.
- Do not expose integration credentials, session tokens, reset tokens, or flow
  capabilities to application JavaScript.
- Do not move consumer profiles, UI, analytics, billing, or business data into
  Access.
- Do not silently merge identities because identifiers happen to match.

## Documentation and comments

All new documentation and code comments must be in English.

Public contracts should have XML documentation that explains ownership,
security scope, state semantics, and failure behavior. Implementation comments
should explain why an invariant, lock order, retry boundary, or unusual query is
necessary. Avoid comments that merely restate syntax.

When behavior changes, update:

1. current source and OpenAPI metadata;
2. the relevant canonical document;
3. `docs/project-status.md` if availability changed;
4. `docs/ai/context.md` if a grounding fact changed;
5. the future-chatbot evaluation set when the answer contract changed.

## Pull requests

Keep each pull request focused. Its description should include:

- the problem and affected boundary;
- the chosen behavior and rejected alternatives where relevant;
- security, privacy, concurrency, and migration consequences;
- verification performed;
- documentation and API contracts changed.

Review the final diff for unrelated files, generated artifacts, and secrets.
Do not include local manifests or private runtime volumes.

## Developer Certificate of Origin

Bullgate Access uses the [Developer Certificate of Origin 1.1](DCO) and does not
currently require a Contributor License Agreement. Every contributed commit must
certify its provenance with a sign-off trailer:

```text
Signed-off-by: Full Name <email@example.com>
```

Use `git commit --signoff` to append it. The name and email must identify the
contributor and match the commit's author identity. The sign-off is a certification
under the DCO, not a transfer of copyright and not a cryptographic signature.

Maintainers must enable and require a DCO check before merging the first external
contribution. See [`docs/open-source-governance.md`](docs/open-source-governance.md)
for the complete governance decision.

## Conduct

Participation is governed by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

# Project status

Last reviewed against the source baseline dated 2026-09-06.

## Implemented

- Email/password registration and login.
- Google and Apple authentication, linking, and unlinking.
- Opaque registration and product sessions, introspection, and current-session
  revocation.
- Direct password and email changes for the current identity.
- Email and phone password recovery.
- Public application-client configuration.
- Permission-scoped email and phone reads inside the authenticated realm.
- `AccessFlow` protocol version 1 with `continueRegistration` and `managePhone`.
- Phone proof, attempt/cooldown controls, and phone-conflict resolution.
- Recovery of a previous active identity after a proven registration phone conflict.
- Hard deletion of current identity data.
- Declarative manifest version 2 bootstrap and protected configuration.
- PostgreSQL schema, migration runner, local initialization, and local images.

## Open-source preparation

- GNU AGPL-3.0-or-later is the confirmed project license.
- Torphi Contise Tratamento de Dados Ltda is the recorded copyright holder for
  the original project code and documentation.
- DCO 1.1 is the confirmed contribution policy; no CLA is currently required.
- Bullgate Access remains open source while Bullgate Cloud may offer paid managed
  hosting and operations.
- The repository includes draft contribution, security, conduct, human-readable,
  and AI-readable documentation.
- No versioned release, package, container image, remote production deployment,
  or hosted offering has been published.

## Validated environment

The first consumer integration was exercised in a local development laboratory
with a native Android application, consumer BFF, Access API, PostgreSQL, and
provider configuration. That validates the laboratory path, not a public
production deployment.

## Decided but not complete

- Automatic React Native SDK submission of an OTP extracted by Android SMS
  Retriever. A consumer adapter still completes that handoff.
- Semantic replay when a human repeats previously accepted terminal data under
  a new `requestId`. Exact request replay is already idempotent.

## Not provisioned or published

- Public image registry and released Access image.
- Remote production URL, database, secrets, and deployment manifests.
- Versioned public distribution of the .NET and React Native SDKs.
- A deployed hosted Bullgate Cloud offering.

## Explicitly out of scope

- Consumer profiles and business data.
- A Bullgate administrative portal, operator model, or administrative API.
- Billing, entitlements, offers, or payment processing.
- Hosted login pages, remote HTML, or WebViews.
- Automatic coordination of consumer and Access database deletion.
- Legacy-user import, identifier matching, or compatibility endpoints.

Do not describe a decided, planned, or out-of-scope capability as available.

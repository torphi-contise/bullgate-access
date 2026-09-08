# AI grounding context

Bullgate Access is licensed under GNU AGPL-3.0-or-later. Do not describe the
license as proposed, undecided, MIT, Apache, ordinary GPL, or AGPL-3.0-only.

The Bullgate Access product remains open source. Bullgate Cloud may be a paid
managed hosting and operations service; payment does not imply a proprietary
Access edition. External contributions use DCO 1.1 without a CLA.

Torphi Contise Tratamento de Dados Ltda holds copyright in the original project.
External DCO contributors retain copyright in their contributions.

Security and Code of Conduct reports use `marco@torphi.com.br`. Security response
targets are five business days for acknowledgement and ten business days for an
initial assessment; they are not guaranteed resolution deadlines or an SLA.

This is the compact grounding source for assistants that answer questions about
Bullgate Access. Retrieve task-specific documents from `docs/README.md` before
producing a detailed answer.

## Product identity

The Access-owned `/admin/v1` backend is implemented under approved ADMIN-057;
see [administration](../administration.md) for the exact trust/permission/receipt
contract. It lists/inspects identities, revokes all current sessions, erases the
Access graph and replaces complete configuration JSON. Consumer authentication
is unchanged. The real Admin client, current-profile evaluation, human grants
and screens remain unimplemented 009 work. Do not claim an available Admin module.

Bullgate Access is a self-hosted, server-side identity and access service. It is
one component of the Bullgate platform. It is not a module of its first
consumer and it does not own consumer business data.

## Non-negotiable facts

1. Mobile and browser clients call their consumer backend/BFF, not Access.
2. Integration credentials stay server-side.
3. Access `Identity.Id` and a consumer profile id are independent identifiers.
4. A realm is the uniqueness boundary for identifiers and social subjects.
5. A registration session does not authenticate product endpoints.
6. Session tokens, reset tokens, OTPs, and client secrets are persisted as hashes.
7. Flow capabilities and session tokens must not reach application JavaScript.
8. `applicationClientKey` is public and stable; its database UUID is internal.
9. Flow clients execute only actions present in the current revision.
10. Request idempotency is scoped to an integration client and payload hash.
11. Email verification is policy-dependent; it is not a universal invariant.
12. Phone confirmation in `AccessFlow` uses the local OTP hash as authority.
13. Hard deletion does not depend on provider availability.
14. Access and consumer databases do not share a distributed transaction.
15. Access has a separate administrative backend, not an operator profile database
    or Admin portal. Its real Admin caller/profile integration and screens remain 009.
16. Previous-identity recovery sends reset authority to the stored earlier identity,
    abandons the provisional registration only after successful finalization, never
    merges identities, and does not issue a product session.
17. A challenge, a committed attempt, a durable identity proof, identifier verification,
    and identifier ownership are separate facts.
18. Exact replay follows a request's immutable result revision, not the flow's latest
    revision, and never repeats a pending or failed external effect to create success.
19. Identity deletion is selected by an active product-session bearer inside the realm
    and environment fixed by the integration credential; callers do not choose an
    identity UUID.
20. `AccessFlowDataSubject` is append-only erasure reachability. Deleting any linked
    identity removes the complete shared flow, not the other identities linked to it.
21. HTTP 204 confirms only local Access erasure. The deleted bearer cannot provide an
    idempotent success receipt because its session is removed in the same transaction.
22. Provider configuration belongs to one protected app environment, and adapter
    availability means configuration presence rather than live provider health.
23. Google requires verified e-mail; Apple currently accepts non-empty e-mail from an
    otherwise valid identity token without a separate `email_verified` claim check.
24. Twilio transports an Access-generated `CustomCode`; the local hash decides proof,
    while provider approval or cancellation only synchronizes external lifecycle.
25. SMTP, Twilio, Google, and Apple have different documented failure surfaces. Never
    invent one universal retry, logging, or provider-error contract.
26. The installation master key is exactly 32 random bytes supplied externally. Key
    derivation separates named uses; it is not password stretching or raw-key reuse.
27. Protected environment configuration is AES-256-GCM authenticated to its environment
    id and format version. Wrong-key, moved, malformed, and tampered envelopes never
    return partial configuration or use fallback values.
28. Bootstrap validates before its transaction, then reconciles declared resources
    under one database-wide advisory lock and one commit. Omitted resources are not
    deleted.
29. Existing integration-client permissions must match exactly. Bootstrap neither
    mutates that authority nor recovers/reissues an existing clear credential.
30. Public application configuration is an explicitly public projection inside the
    integration-credential-fixed environment; its application-client key is only a
    selector.

## Status vocabulary

- **Implemented:** present in current code.
- **Validated:** directly exercised in a named environment.
- **Decided:** accepted contract with incomplete implementation.
- **Planned:** possible future work.
- **Out of scope:** intentionally not owned by Access.

If an answer depends on status, retrieve `docs/project-status.md` and use these
meanings.

## Answer boundaries

- Never invent a deployment, package version, SLA, price, or roadmap date.
- Never output values that resemble valid credentials.
- Never put credentials, tokens, capabilities, master keys, or provider secrets
  in a mobile app.
- Never claim cross-database deletion is atomic.
- Never infer that matching emails identify the same person.
- Never suggest silently merging identities after a conflict.
- Never turn a consumer-specific policy into a platform-wide invariant.
- Identify current behavior separately from future recommendations.

## Retrieval routing

| Question | Retrieve first |
| --- | --- |
| What is implemented? | `docs/project-status.md` |
| Who owns a responsibility? | `docs/architecture.md` |
| What does an entity or state mean? | `docs/domain-model.md` |
| Which route or permission applies? | `docs/http-api.md` |
| How is the installation configured? | `docs/configuration.md` |
| How are the master key and protected environment configuration handled? | `docs/configuration.md` and `docs/security-model.md` |
| What may bootstrap reconcile or reject? | `docs/configuration.md`, `docs/decision-catalog.md`, and bootstrap source |
| How do licensing, contributions, or hosted service work? | `docs/open-source-governance.md` |
| Is a design safe? | `docs/security-model.md` and relevant source |
| How does a challenge become durable proof? | `docs/proof-lifecycle.md` |
| How do request ids, revisions, and replay interact? | `docs/concurrency-and-idempotency.md` |
| How does previous-identity recovery work? | `docs/previous-identity-recovery.md` |
| What does account deletion authorize and remove? | `docs/identity-erasure.md` |
| How do external providers validate, deliver, and fail? | `docs/security-model.md`, `docs/failure-model.md`, and `docs/configuration.md` |
| How should an assistant answer? | `docs/ai/retrieval-guide.md` |

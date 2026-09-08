# Documentation map

This directory is the canonical documentation entry point for Bullgate Access.
It is designed for maintainers, integrators, and retrieval-based assistants.

## Required reading order

Read these documents in order before changing behavior or answering detailed
questions about the service:

1. [`project-status.md`](project-status.md)
2. [`architecture.md`](architecture.md)
3. [`domain-model.md`](domain-model.md)
4. [`security-model.md`](security-model.md)
5. The task-specific document:
   - integration: [`integration-guide.md`](integration-guide.md)
   - API transport: [`http-api.md`](http-api.md)
   - Access administrative backend and trusted Admin calls: [`administration.md`](administration.md)
   - stateful journeys: [`access-flow.md`](access-flow.md)
   - proof challenges, attempts, and durable evidence:
     [`proof-lifecycle.md`](proof-lifecycle.md)
   - recovery of an earlier account after a proven phone conflict:
     [`previous-identity-recovery.md`](previous-identity-recovery.md)
   - current-identity hard deletion and historical flow reachability:
     [`identity-erasure.md`](identity-erasure.md)
   - retries and overlapping operations:
     [`concurrency-and-idempotency.md`](concurrency-and-idempotency.md)
   - error handling: [`failure-model.md`](failure-model.md)
   - installation or tenancy: [`configuration.md`](configuration.md)
   - assistant or search ingestion: [`ai/context.md`](ai/context.md) and
     [`ai/retrieval-guide.md`](ai/retrieval-guide.md)
   - source documentation: [`commenting-guide.md`](commenting-guide.md)
   - licensing, contributions, and hosted service:
     [`open-source-governance.md`](open-source-governance.md)

The controlled vocabulary for retrieval lives in [`ai/glossary.md`](ai/glossary.md).
The baseline chatbot checks live in [`ai/evaluation-set.md`](ai/evaluation-set.md).
Cross-cutting reasons and closed choices live in
[`decision-catalog.md`](decision-catalog.md).

The list is closed. A new canonical document must be added here in the correct
reading position.

## Trust order

Use this order when sources disagree:

1. current executable source and database mappings;
2. generated OpenAPI from the same revision;
3. this canonical documentation;
4. examples and historical discussions.

Documentation describes a revision; it does not override code. A mismatch is a
documentation defect unless an approved change explicitly says that the code
must change.

## Status language

- **Implemented** — present in the current source tree.
- **Validated** — directly exercised in the stated environment.
- **Decided** — a contract has been accepted but is not fully implemented.
- **Planned** — a possible future direction, not a current capability.
- **Out of scope** — intentionally outside this service boundary.

Never replace these labels with vague words such as "supported" when the actual
state matters.

## Documentation style

- Write in English.
- Define a term before using its abbreviation.
- Name the owning component for every stateful responsibility.
- Separate protocol contracts from product user-interface behavior.
- Describe invariants and failure behavior, not only happy paths.
- Do not include secrets, valid tokens, private endpoints, or personal data.
- Link to code by stable type or path; avoid volatile line numbers in prose.

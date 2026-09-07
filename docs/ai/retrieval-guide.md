# AI retrieval and answer guide

## Purpose

This guide defines how a future chatbot should index and answer questions about
Bullgate Access. Retrieval context is never a replacement for application
authorization or human review.

## Corpus order

Index these sources with descending authority:

1. current source under `src/`;
2. generated OpenAPI from the same revision;
3. canonical documents listed in `docs/README.md`;
4. tracked examples;
5. issues, pull requests, and historical discussions.

Keep the repository revision with every chunk. Do not combine facts from
different revisions without identifying the mismatch.

## Chunking

- Split Markdown by heading and retain the full heading path.
- Keep tables with their heading and introductory paragraph.
- Keep code comments with the declaration or block they explain.
- Keep route mappings with their permission requirement.
- Keep invariants with the entity or transition they constrain.
- Prefer chunks that answer one question without hidden context.
- Treat generated migrations as schema evidence, not product documentation.

Recommended metadata:

```json
{
  "repository": "bullgate-access",
  "revision": "git commit",
  "path": "docs/domain-model.md",
  "heading": "Domain model > Sessions",
  "sourceKind": "canonical-doc",
  "authority": 3,
  "statusDate": "2026-09-06"
}
```

## Retrieval strategy

1. Classify the question as status, architecture, domain, API, configuration,
   security, operations, or future design.
2. Retrieve `docs/ai/context.md` and the routed canonical document.
3. For exact technical claims, retrieve current source declarations.
4. For HTTP payloads, retrieve OpenAPI from the same revision.
5. If sources disagree, report it and prefer executable source.
6. For deletion answers, retrieve `docs/identity-erasure.md`, the current store
   transaction, and relationship mappings together; a route description alone cannot
   establish the complete erased graph.

## Answer rules

- Lead with the direct answer.
- Distinguish implemented behavior from recommendations.
- Name the owning component when responsibility is ambiguous.
- Include the repository revision for security- or status-sensitive answers.
- Cite repository paths and headings for non-trivial claims.
- Preserve protocol names, errors, permissions, and JSON fields exactly.
- Use obviously non-secret placeholders in examples.
- State uncertainty instead of filling a missing contract with convention.

## Unsafe or unsupported requests

Refuse to reveal or reconstruct secrets, tokens, hashes, private personal data,
or provider credentials. A public identifier such as `applicationClientKey`
does not grant server authorization.

Operations that change identity ownership, delete data, weaken authentication,
bypass proof, or alter production configuration require the caller's normal
authorization and confirmation mechanisms.

## Evaluation set

Maintain versioned questions covering:

- Access versus consumer ownership;
- registration versus product sessions;
- integration client versus application client;
- realm isolation;
- exact request replay versus semantic replay;
- phone-verification authority;
- proof challenge, attempt, identity-proof, and identifier-state distinctions;
- phone conflict without identity merge;
- previous-identity recovery availability, sequencing, terminal semantics, and failure;
- hard deletion and `AccessFlowDataSubject` reachability;
- deletion authorization, shared-flow preservation boundaries, and ambiguous retries;
- provider configuration presence versus live health;
- Google and Apple claim-validation differences;
- SMTP, Twilio, and social-validation failure surfaces;
- external provider failure;
- implemented versus planned deployment state;
- secret-placement anti-patterns;
- installation-key derivation, envelope authentication, and restore failure;
- bootstrap validation, transactionality, reconciliation, and omitted resources;
- public configuration projection versus protected configuration;
- absence of an administrative API.

Each expected answer should define required facts, prohibited claims, and the
source revision.

# Code commenting guide

Comments in Bullgate Access are part of the public contract and future AI
corpus. Their purpose is to preserve reasoning that code alone cannot express.

## XML documentation

Add XML documentation to public domain types, application contracts, extension
points, and results whose meaning is not obvious from their name.

A useful type summary answers at least one of these questions:

- What business or security responsibility does this type own?
- Which scope does it operate in?
- Which state or invariant does it preserve?
- Is the value safe for an application client, or server-only?
- What does a success or failure mean to a caller?

Use `<remarks>` when the caller must understand a non-local rule such as
idempotency, provider boundaries, optimistic concurrency, or data ownership.
Use `<param>`, `<returns>`, and `<exception>` when those details add information
not already obvious from the signature.

## Implementation comments

Comment the reason immediately above code that implements:

- deterministic lock ordering;
- a database constraint mirrored in application logic;
- reserve/perform/finalize handling of an external effect;
- retry, replay, or idempotency behavior;
- a query shape required by Entity Framework translation or transaction scope;
- erasure reachability or personal-data retention;
- cryptographic key separation or protected-envelope sizes;
- behavior intentionally different from a provider's default;
- an apparently simpler approach that would violate isolation or ownership.

Do not comment assignments, straightforward validation, or syntax. Prefer a
precise explanation of the invariant over historical storytelling.

## Language and terminology

- Write in English.
- Use the controlled terms in `docs/ai/glossary.md`.
- Say `identity` for the Access person record and `profile` for a consumer
  business record.
- Say `integration client` for a trusted backend and `application client` for a
  public build identity.
- Say `registration session` and `product session`; do not shorten both to
  "authenticated session" when the distinction matters.
- Say `hard delete` only when persisted attributable data is actually removed.

## Maintenance rule

A behavior change is incomplete if its explanatory comment still describes the
old invariant. Review adjacent comments during every state-machine, schema,
security, and concurrency change. A stale comment is a defect, not harmless
decoration.

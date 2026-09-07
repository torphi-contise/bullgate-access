# Controlled glossary

Use these meanings consistently in documentation, code comments, search
metadata, and chatbot answers.

| Term | Meaning | Do not confuse with |
| --- | --- | --- |
| Access | The Bullgate identity and access service in this repository. | The entire Bullgate platform or a consumer product. |
| Identity | A person recognized inside one Access realm. | A consumer business profile. |
| Identifier | A normalized way to locate an identity, currently email or phone. | An authenticator or proof. |
| Authenticator | A means of authenticating, such as password, Google, or Apple. | An identifier that happens to carry an email. |
| Realm | The uniqueness and isolation boundary for identities, identifiers, and social subjects. | An app environment or deployment cluster. |
| App environment | An app-to-realm binding that owns policy and configuration. | A realm; multiple environments may use one realm. |
| Integration client | A trusted server client with a secret credential and permissions. | An application client or mobile app. |
| Application client | A public, stable identity for a client build and its public metadata. | A secret credential or database UUID. |
| Integration credential | Opaque server bearer credential beginning with the project-defined prefix. | A public application-client key. |
| Installation master key | External 32-byte random root key from which named Access uses derive independent keys. | A password, a provider secret, or a key stored in PostgreSQL. |
| Protected environment configuration | Strict environment-owned policy/provider document stored as an AES-GCM authenticated envelope. | Public application configuration or queryable policy columns alone. |
| Public configuration projection | Explicitly public common and application-client metadata selected inside an already authenticated environment. | The complete decrypted environment configuration or authorization. |
| Bootstrap reconciliation | Atomic create-or-verify/update processing for resources declared in one manifest. | Destructive desired-state deletion, credential rotation, or an administrative API. |
| Registration context | Persisted progress of registration in an environment. | An `AccessFlow`; phone management has no registration context. |
| Registration session | Restricted session for completing registration. | A product-authenticated session. |
| Product session | Session eligible for consumer-profile resolution by a BFF. | The consumer profile itself. |
| AccessFlow | Versioned, persisted, capability-protected multi-step journey. | A screen flow implemented by a consumer UI. |
| Flow capability | Opaque authority to read or act on one flow. | A flow id or application-client key. |
| Revision | Optimistic version of an `AccessFlow` snapshot. | A Git revision or protocol version. |
| Request id | Caller-provided idempotency key scoped to an integration client. | A flow id or action id. |
| Result revision | Immutable flow snapshot originally produced by one committed request. | The flow's latest current revision. |
| Exact replay | Reuse of request id and identical payload, returning the persisted result. | Semantic repetition under a new request id. |
| Pending external request | Durable ownership of an in-flight provider effect without a committed result revision. | Proof that delivery succeeded or failed. |
| Proof challenge | Expiring challenge whose secret is stored as a hash. | An `IdentityProof`, which records completed proof. |
| Proof attempt | Immutable fact that one secret comparison committed. | Standalone authorization or durable possession proof. |
| Identity proof | Durable evidence materialized from one successfully confirmed challenge. | Identifier ownership, a sent message, or a successful attempt by itself. |
| Confirming challenge | Exclusive reservation held by one successful local comparison while final proof state commits. | A second active code or proof that finalization already succeeded. |
| Provider reference | External delivery or validation correlation value. | Local proof authority or a credential. |
| Provider availability | Presence of usable provider configuration in the selected protected environment. | A network health check, reachability guarantee, or delivery prediction. |
| Provider acceptance | The external boundary accepted an operation according to its adapter contract. | Inbox or handset receipt, human action, identity proof, or an atomic database commit. |
| Provider lifecycle update | Approval or cancellation of a previously created external verification resource. | A second OTP-validity decision or rollback of an already delivered message. |
| Social identity assertion | Provider-validated subject, e-mail, and optional display metadata normalized for the application service. | Raw provider token, consumer profile, identity merge authority, or proof that every optional claim exists. |
| Phone conflict | A proven phone is already owned by another identity in the realm. | Permission to merge identities. |
| Previous-identity recovery | Registration-only path that sends password recovery to the stored earlier identity and abandons the provisional identity after successful finalization. | Identity merge, phone transfer, completed password reset, or immediate product login. |
| Abandoned identity | Provisional identity closed during recovery of a previous identity. | Soft deletion or user-requested erasure. |
| Data subject link | Append-only reachability from an AccessFlow to an identity whose personal data the complete flow graph retains. | Current flow ownership, current phone ownership, or a relationship that deletes every linked identity. |
| Hard delete | Removal of attributable Access data in one local Access database transaction. | Abandonment, provider-account deletion, or cross-database atomic deletion. |
| Deletion receipt | Durable evidence that a named deletion operation committed. | HTTP 401 from retrying a bearer whose session may already have been deleted. |
| BFF | Backend for Frontend that owns cookies and calls Access server-to-server. | Bullgate Access itself. |

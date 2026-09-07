# Open-source governance

This document records the licensing, contribution, and commercial-hosting model
for Bullgate Access. It describes current project policy, not general legal advice.

## Source license

Bullgate Access is licensed under GNU AGPL-3.0-or-later. Recipients may use
version 3 or a later version published by the Free Software Foundation. The
complete, unmodified version 3 text is in the repository root `LICENSE` file.

The Access product, including functionality accepted from external contributors,
remains open source under AGPL-3.0-or-later. Do not describe a feature inside Bullgate
Access as a closed-source or proprietary edition.

## Hosted commercial service

An official paid hosted offering may be provided as Bullgate Cloud. Customers pay
for operating the service, including managed infrastructure, upgrades, availability,
backup, monitoring, support, configuration, isolation, and related operational work.

Charging for that service does not change the source license. Modifications to the
AGPL-covered service that are used for remote network interaction must preserve the
applicable source-availability obligations. The hosted offering must provide a clear
way for its users to obtain the corresponding source when required.

Pricing, service-level agreements, regions, support tiers, and availability are not
defined by this repository unless an explicitly versioned commercial document says
otherwise.

## Incoming contributions

Bullgate Access uses the Developer Certificate of Origin version 1.1 (DCO 1.1),
stored in the repository root `DCO` file. It does not currently require a Contributor
License Agreement.

Every contributed commit must carry a sign-off trailer whose name and email match
the contributor's Git identity:

```text
Signed-off-by: Full Name <email@example.com>
```

Git can append the trailer with `git commit --signoff`. The trailer is a contributor
certification under the DCO; it is not the same as a GPG or SSH cryptographic commit
signature.

The project should enforce DCO on pull requests before accepting external
contributions. Installing a GitHub app, enabling a required check, or changing branch
protection is repository administration and is not performed merely by adding these
files.

## Copyright and relicensing

Copyright in the original Bullgate Access code and documentation is held by
Torphi Contise Tratamento de Dados Ltda, beginning with the repository's 2026
history. The canonical ownership notice is `COPYRIGHT.md`.

Contributors retain copyright in their contributions. The DCO certifies provenance
and the right to submit under the repository license; it does not assign copyright to
the project owner.

Because external contributors retain their rights, a future attempt to relicense
their work or incorporate it into a proprietary version may require their permission.
That limitation is accepted by the current decision to keep Bullgate Access open
source. A materially different commercial licensing strategy requires a new explicit
decision and appropriate legal review before contributions are accepted under it.

## Boundary with other Bullgate products

Bullgate Cloud operations, consumer applications, and separately developed services
may have their own business and licensing models. Their technical separation from
Bullgate Access must be real and documented; a filename, process, repository, plugin
label, or deployment boundary alone does not settle whether software is a derivative
work.

Consult qualified counsel before relying on a boundary to keep combined functionality
proprietary. Project documentation must not offer legal conclusions about a specific
deployment.

## Security and conduct contacts

Private security reports and Code of Conduct reports use
`marco@torphi.com.br`, with the subject lines defined in `SECURITY.md` and
`CODE_OF_CONDUCT.md`.

The project aims to acknowledge a vulnerability report within five business days and
provide an initial assessment within ten business days. These are communication
targets, not guaranteed remediation deadlines or service-level agreements.

# Minority Prophet Border

> **Status: public neutral specification and adapter boundary.** Production
> provider configuration, credentials, and private wire contracts never belong
> in this repository.

Minority Prophet Border defines a portable admission record for one exact
agent action. The record binds authority, declaration, destination policy,
human intervention, and action data for verification at one or more Gates.

```text
authority provider      agent declaration       destination policy
        \                       |                       /
         \                      |                      /
          +---- portable Border admission receipt ----+
                                |
                     one or more compatible Gates
                                |
                      destination runtime adapter
```

## Three layers, three parties

| Layer | Party | Responsibility |
| --- | --- | --- |
| **Authority providers** | identity and delegation systems | Prove who acts, for whom, under what scope and time box. |
| **The Border** | this repository | Admit only verifiable identity, authority, and evidence; then witness approved crossings. |
| **A Gate** | Minority Prophet Gate | At the Border or downstream, decide consequences: proceed, block, or escalate. |

## Neutral contract

The provider-independent contract in `border/` defines the facts an
identity/authority implementation supplies and the bindings a Gate verifies.

```text
identity/authority implementation
                    ↓
       neutral Border authority envelope
                    ↓
          provider-blind Gate decision
                    ↓
        neutral runtime adapter contract
                    ↓
             runtime implementation
```

### Optional authorized-invocation (Mandate) adapter

Some actions do not transfer authority from one agent to another. Agent A may
be authorized to request one exact action while Agent B independently holds
the permission needed to execute it. `border.mandate_adapter` verifies both
paths and emits a provider-neutral `border-authority-relation/v1` receipt,
stamped with Border's existing DSSE/in-toto machinery, without mislabeling the
relationship as delegation.

For example, A may request archiving `notion:page:123`, while B independently
has Notion permission to execute `archive_page`. Border admits the relation
only when both permissions, A's signed Mandate, B's bound credential, the exact
page/action/payload, audience, time, and revocation status verify. The adapter
is optional; native artifacts may still travel directly to a compatible Gate.

The contract and threat boundary are documented in
[`schema/authorized_invocation.md`](schema/authorized_invocation.md), with
language-neutral cases in
[`conformance/mandate-v1.json`](conformance/mandate-v1.json).

**Issuers credential the travelers, borders witness the crossings, gates guard
the consequences — and nothing between a border and a gate can create
evidence, only carry it.**

### Optional subject-link seam

Deployments that must combine identity forms from different provider
namespaces can normalize their signed link receipts with
`border.subject_link`. The implementer states the required credential types,
audience, and minimum provider count; the seam returns `accept`, `block`, or
`escalate` for that explicit requirement.

This seam is optional. A direct provider-to-runtime integration that already
supplies one sufficient, verifiable composite identity does not need it. The
seam does not perform identity proofing, match names or attributes, store a
person profile, grant authority, or establish that differently named providers
are independent. It only checks explicit provider-issued links and normalizes
the minimum facts Border needs.

### Verifier-independence invariant

A verifier is not trusted merely because it is a third party. It earns trust
by applying transparent rules, remaining independent of the evidence producer,
exposing uncertainty, and being unable to mint, alter, or promote the evidence
it verifies.

The current Border envelope records an asserted `independence_basis`, rejects
unknown origins that claim independence, and prevents copied or derived
evidence from minting a fresh root. It does **not** yet establish whether an
evidence producer and verifier share an organizational controller. Until a
versioned control-domain profile and external verification policy exist, a
deployment must not treat different names, keys, services, or labels as proof
of independence. Unknown or overlapping control is a reason for secondary
review, never a new source of authority. The preregistered HVI-1 study in the
Minority Prophet research repository defines the experiment required to test
that future profile.

Issuers give agents their passports; the Border binds an exact declaration to
current authority and destination policy; the first Gate evaluates that bound
record before anything acts. Separate witnesses may later stamp observations
created at approved execution boundaries for downstream Gates.

## The two-ID rule

A manifest answers **MAY-YOU-TESTIFY**. An entry stamp answers
**IS-THIS-TESTIMONY-GROUNDED-CURRENT-AND-ABOUT-THIS-CASE**. The Gate requires
both per claim; thinness in either is an escalation, never a substitute for
evidence.

## Scope

The Border never judges truth, quality, or policy. Its **admission path is
active and fail-closed**: unverifiable identity, authority, signatures,
bindings, or evidence do not cross the Border. Once material is admitted, the
**witness path is observational and non-blocking**: it emits an in-toto
Statement in a DSSE envelope at explicitly approved tool-boundary crossings.
A witness-write failure may fail open and remain local to a spool, but that
exception never converts failed admission into valid authority. Rekor logging
is optional and **off by default** for the private deployment phase.

A Gate may be colocated with the Border to decide whether admitted material
may enter. Additional Gates may be placed downstream before reasoning,
delegation, data access, tool dispatch, publication, payment, or any other
consequence. Every Gate consumes the same neutral evidence contract but applies
policy for its own decision point.

- [`schema/entry_stamp.md`](schema/entry_stamp.md) — schema and security
  rationale for each field.
- [`border/boundaries.py`](border/boundaries.py) — owner-gated root policy.
- [`SECURITY.md`](SECURITY.md) — key and root-policy threat model.
- [`docs/deployment.md`](docs/deployment.md) — separable deployment model.
- [`docs/witness-spike.md`](docs/witness-spike.md) — bounded evaluation of
  Witness for CI-shaped roots.
- [`border/authority_adapter.py`](border/authority_adapter.py) — neutral,
  fail-closed identity/authority normalization.
- [`border/reference_authorities.py`](border/reference_authorities.py) —
  signed-token and capability-grant reference provider adapters.
- [`border/adapter_maker.py`](border/adapter_maker.py) — provider profile and
  adapter-package generator with explicit gap reporting.
- [`border/admission.py`](border/admission.py) — practical trip-declaration,
  authority, runtime-policy, and human-control binding.
- [`border/jcs.py`](border/jcs.py) — float-free RFC 8785-compatible canonical
  JSON profile for portable security-critical digests.
- [`border/dsse.py`](border/dsse.py) — DSSE/in-toto admission packaging with
  injected production signer and verifier callbacks.
- [`schema/admission.md`](schema/admission.md) — the admission flow and signed
  sockets checked by every Gate.
- [`conformance/`](conformance/) — language-neutral admission vectors and
  adversarial expected outcomes.
- [`docs/openid-aiim-2026.md`](docs/openid-aiim-2026.md) — executable OpenID
  AIIM gateway interoperability path and partner result contract.
- [`docs/openid-aiim-deployment.md`](docs/openid-aiim-deployment.md) — public
  endpoint, readiness, protected-configuration and bilateral-run contract.
- [`docs/live-sandbox.md`](docs/live-sandbox.md) — container-ready MCP server
  surface joining OAuth verification, Border binding, Gate enforcement, and a
  durable harmless echo adapter.
- [`docs/local-bilateral-rehearsal.md`](docs/local-bilateral-rehearsal.md) —
  one-command, local-only OAuth/MCP rehearsal with explicit non-claims.

## Deferred work

Production key backends, durable multi-process replay storage, and the verifier
bridge remain deployment work. The public code provides DSSE packaging,
injected signer/verifier interfaces, two neutral authority-provider families,
and a four-pair Border/Gate/runtime conformance matrix, but never owns
production keys.

The future verifier bridge must normalize both approved Witness attestation
collections and Border entry-stamp predicates into the same internal Gate
claim shape. The end-to-end suite must include a mixed-source decision.

## License

Licensed under Apache License 2.0. See [`LICENSE`](LICENSE) and
[`NOTICE`](NOTICE).

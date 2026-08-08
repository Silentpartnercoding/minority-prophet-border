# Knowledge-transaction conformance — record contracts

Extracted verbatim from `research/knowledge-ledger/CONFORMANCE-PROFILE-v1.md`
in the minority-prophet research repository, commit `754354d03401`. The rules
below are reproduced without modification; this file adds only this header.

These are **specification-local** rules: they are not theorems from
*Minority Prophet* and the paper makes no claim about them. They are the
engineering properties an implementation needs in order to produce records
that another implementation can verify.

Each rule states its evidence, including where that evidence is thin. Nothing
here is asserted without a count behind it.

Rules in this extract: P1, P2, P3, P5

## P1 — Deterministic replay (KL-000 invariant I4)

**Normative statement.** Evaluating the same world twice yields
byte-identical canonical output and an equal `contentDigest`.

**Why specification-local.** The paper makes no claim about serialisation
determinism; this is reproducibility-of-artifact discipline
(RESEARCH-METHOD's evidence-package requirements).

**Evidence.** Zero violations over 176,120 exhaustive + 1,000,000 randomized
worlds per run, every confirmatory run of both implementations; replay is
checked world-by-world by the shared checker (`check_world`, I4 section).
Cross-implementation: the canonical forms of pinned receipts C11 (703 bytes)
and C12 (691 bytes) are byte-identical across the two implementations
(IND-20260807-3).

## P2 — Digest integrity (KL-000 invariant I6)

**Normative statement.** Every emitted receipt self-verifies
(`contentDigest` = SHA-256 over the canonical bytes of the receipt with the
top-level `contentDigest` member removed, and nothing else removed), and
every single-member mutation of a receipt fails verification.

**Why specification-local.** Tamper-evidence for the audit record,
operationalising the paper's "auditable summary" (§7); the paper specifies
no digest mechanism.

**Evidence.** Zero I6 violations across all phases, both implementations;
the independent implementation additionally verified all 15 single-field
mutations fail on every world in every phase (IND-20260807-1). Digest scope
is fully registered (v1.2.0 R5.1) — eight covered members, every byte
specified; C11/C12 digests reproduce across implementations.

## P3 — Order invariance (KL-000 invariant I7)

**Normative statement.** Permuting the input's records or locations changes
no evidential field, no conclusion, and no `contentDigest`. (Achieved by the
evaluator sorting root lists before emission — ascending Unicode code
point — not by the codec reordering anything.)

**Why specification-local.** The schema-v0.1 shadow of Theorem 1's immunity:
no parent edges exist to rewire, so input reordering is the remaining
transformation, and invariance under it is asserted locally. **Declared
strictly weaker than Theorem 1; it does not test the theorem** (see paper
v1.0.4 [E8]).

**Evidence.** Zero I7 violations across all phases, both implementations;
adversarial A09 (one record copied to fifty, then permuted: identical
digest).

## P5 — Receipt serialisation (registered receipt object + canonical form; TRC-101 rule RO-reporting)

**Normative statement.** The receipt is a closed nine-member object
(`schema`, `transactionId`, `claim`, `search`, `evidence`, `conclusion`,
`reason`, `limits`, `contentDigest` — extra members nonconformant); root
lists sorted ascending by code point; `schema`/`limits` constant strings and
`reason` one of four registered strings; canonical form = UTF-8, keys sorted
by code point, separators `,`/`:`, minimal escaping with raw UTF-8 at and
above U+0020, integers plain base-10.

**Why specification-local.** The paper specifies no receipt serialisation;
this is the machinery that makes cross-implementation byte agreement
possible at all (its absence is exactly why the C11 digest could not be
computed before v1.2.0 registered the object — finding G2).

**Evidence.** C11 and C12 byte-identical across implementations
(IND-20260807-3: member sets equal, canonical forms equal, digests equal);
the independent codec round-trips byte-identically through the registered
realisation; 12 permanent tests pin the object, 8 more pin I12's enforcement
of the values it carries.

---

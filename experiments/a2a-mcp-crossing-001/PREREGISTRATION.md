# A2A-MCP-CROSSING-001 — preregistration

**Status: cases frozen, experiment RUN 18 August 2026 — see `RESULTS.md`.**

Everything below this line is unchanged from before either lane existed, so what
was predicted can be read against what happened. `cases.json` is byte-identical
and still hashes to the digest recorded here.

`cases.json`
sha256 `eea9a7c5ca0e0d90ca308401c9408f0187721c5edeb4a46bffaf2a0484ca12d1`

That digest is recorded here so a later result can be checked against the case
set as it stood before any protection was built. If the cases change, the digest
changes, and any result reported against the old digest is a result about a
different experiment.

## The question

A2A v1.0 describes the likely production architecture as MCP inside agents, A2A
between agents. Both sides authenticate by their own rules.

The under-owned question is not whether either protocol is sound. It is:

> Did the exact authority for action X survive the handoff from an A2A task into
> an MCP tool invocation, without substitution?

A composition can be correct on each side and still be composed incorrectly at
the seam. That is an inference from where the protocol boundaries fall, **not a
claim that A2A or MCP is broken.**

## What is deliberately not claimed

This experiment does not assert that an exploitable A2A/MCP defect exists.
Five of the six cases predict `unknown` for the native lane, and they are
unknown on purpose. Guessing them and then confirming the guess is how a
preregistration becomes decoration.

The conclusion has to be earned by running this.

## Two lanes

| Lane | Composition |
|---|---|
| **native** | A2A caller and MCP server composed directly, each side authenticating by its own rules, no crossing receipt. |
| **bound** | The identical composition with a Border exact-crossing binding carried as an A2A extension reference, rechecked by Gate before the MCP action runs. |

A2A provides an extension mechanism on messages and artifacts, so the bound lane
carries a digest or reference to a Border receipt **without forking A2A**. No new
protocol is proposed and nothing is submitted to any foundation.

The action is `interop.echo`, the harmless side-effect-free path already used by
`border/live_sandbox.py`. The experiment is about whether authority survived a
handoff, not about causing an effect.

## The six cases

Frozen in `cases.json`: valid crossing; substituted A2A caller; substituted
taskId/contextId; changed MCP tool or payload; replayed authorization; expired
or revoked authority.

## What would make this interesting, stated in advance

**Interesting** — `valid_crossing` succeeds in **both** lanes, **and** at least
one of the five mutations passes ordinary component checks in the native lane
while being rejected in the bound lane.

**Void** — `valid_crossing` fails in either lane. Every later refusal would then
be consistent with a broken lane rather than a seam defect, and nothing could be
concluded.

**Refuted** — every mutation is already caught natively. There is then no seam
gap to own. That result gets published here rather than discarded; an experiment
that can only report one outcome is not an experiment.

## Provenance of the premises

Verified at source on 18 August 2026:

- `a2aproject/A2A` exists, is public, is not archived, and released **v1.0.0 on
  12 March 2026** (v1.0.1 on 28 May 2026). "Production-ready" is fair;
  "brand new" would not be — v1.0 is five months old.
- `border/live_sandbox.py` on `main` composes a verified OAuth ceiling bound by
  Border, rechecked by Gate, before a harmless `interop.echo` action reaches the
  runtime adapter.

Not verified, and not relied on by anything above: reports that A2A is moving
into the Agentic AI Foundation, and any characterisation of that foundation's
intake. The experiment does not depend on them being true.

## Next step

Implement the two lanes and run the frozen cases. Record every outcome,
including the boring ones, against the digest above.

**Done.** `RESULTS.md` and `results.json`. Verdict: interesting — the valid path
succeeded in both lanes and all five mutations took effect natively while the
bound lane refused them. The results also record a measurement correction and
the fidelity limits of the run.

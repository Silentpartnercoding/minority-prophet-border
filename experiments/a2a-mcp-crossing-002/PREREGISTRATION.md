# A2A-MCP-CROSSING-002 — preregistration

**Status: cases frozen 19 August 2026. NOT YET RUN.** Neither lane exists. No result is
claimed by this document, and if one is later reported against a different `cases.json` it is
a result about a different experiment.

`cases.json`
sha256 `8e6e393d7b6701e62ab9ffbc19a14ac271d48e3aca601a6bc7547979eabc4ac4`

## The question

A2A-MCP-CROSSING-001 composed an A2A caller and an MCP server **directly**. Production
deployments generally do not. They put a gateway in the middle, and that gateway is a principal
in its own right: it registers each downstream agent along with its own credential for reaching
it — bearer, basic, or OAuth.

So the intermediary does not merely relay. It authenticates downstream **as itself**.

> When a crossing binding passes through an intermediary that holds its own downstream
> credential, does the binding still refuse the same substitutions — or does the intermediary's
> identity silently replace the one the binding names?

001 established that without a crossing artifact, five substitutions at the seam take effect.
It did not establish that the artifact keeps working once something with its own keys stands in
the path. Those are different claims, and only the first has been measured.

## What is deliberately not claimed

**No product is being modelled or accused.** The broker's shape is taken from a composition
pattern observed during the 2026-08-19 refutation check, not copied from any implementation, and
no claim is made that any named gateway behaves as the brokered lane behaves.

**No direction is claimed to be more common.** Whether A2A→MCP or MCP→A2A dominates in
production is a survey question. This experiment cannot answer it and does not try.

**Five of the six cases predict `unknown`, and they are unknown on purpose.** The one prediction
recorded is for the control, because a control that is not predicted to pass is not a control.
Guessing the other five and then confirming the guess is how a preregistration becomes
decoration.

## Two lanes

| Lane | Composition |
|---|---|
| **direct** | 001's bound lane, unchanged: caller and MCP server composed directly, crossing binding carried as an A2A extension reference and rechecked before the action runs. Known to refuse all five of 001's mutations. |
| **brokered** | The identical binding, but relayed through an intermediary that holds its own registered downstream credential and performs the downstream call itself. |

The direct lane is the reference, not a straw man. If a mutation is refused in `direct` and
takes effect in `brokered`, the intermediary is what changed.

## The six cases

Frozen in `cases.json`: valid brokered crossing (control); broker substitutes its own identity;
a second caller reuses the broker path; broker forwards a binding it never received; binding
valid but naming a different downstream agent; broker calls after the upstream caller's
authority is revoked while its own credential stays live.

The last is the sharpest, because it is the one where every component is behaving correctly.
The upstream grant is gone. The intermediary's credential is not.

## What would make this interesting, stated in advance

**Interesting** — `valid_brokered_crossing` succeeds in both lanes, **and** at least one mutation
is refused in `direct` while taking effect in `brokered`. That would mean a crossing binding
degrades across an intermediary, and the degradation is the finding.

**Void** — `valid_brokered_crossing` fails in either lane. Every later refusal would then be
consistent with a broken lane rather than a broker-introduced gap, and nothing could be
concluded.

**Refuted** — every mutation refused in `direct` is also refused in `brokered`. The binding
survives the intermediary intact, there is no degradation to own, and 001's result extends to
the brokered shape unchanged. **That outcome gets published here rather than discarded.** An
experiment that can only report one result is not an experiment.

There is a fourth outcome worth naming so it is not mistaken for a bug: a mutation refused in
`brokered` but **not** in `direct`. That would mean the intermediary is doing enforcement work
the direct composition does not, and it is a finding about gateways being load-bearing rather
than transparent.

## Provenance of the premises

Verified 2026-08-19, recorded in `../a2a-mcp-crossing-001/REFUTATION-CHECK.md`:

- `IBM/mcp-context-forge` registers A2A agents with per-agent auth configuration and invokes them
  at `/a2a/{agent_name}/invoke`, i.e. an intermediary holding its own downstream credential is a
  real deployment shape and not a hypothetical.
- The same gateway propagates caller context through `passthrough_headers`, a per-agent whitelist
  of HTTP headers, fail-closed on an empty list. Header forwarding is the mechanism this
  experiment expects to find in the brokered lane's path, and forwarding is not binding.

Not verified and not relied upon: how common either composition direction is, and whether any
specific gateway would pass or fail these cases.

## Next step

Implement the two lanes and run the frozen cases. Record every outcome, including the boring
ones, against the digest above. Do not amend `cases.json`; if the case set needs to change,
that is a new experiment with a new digest.

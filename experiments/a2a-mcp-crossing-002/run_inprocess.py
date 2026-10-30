#!/usr/bin/env python3
"""Run A2A-MCP-CROSSING-002 (cases-r3.json, Amendment 4) in-process, all four arms.

    pip install -r ../a2a-mcp-crossing-001/requirements.txt cryptography
    python3 experiments/a2a-mcp-crossing-002/run_inprocess.py

No sockets, no tokens: identities are handed to the checks by the runner, as in
001's run_experiment.py. The real-transport run is run_transport.py. Writes
results-r4-inprocess.json. The first run's results-inprocess.json came from
commit baceca5 and is left as recorded.
"""

from __future__ import annotations

import asyncio
import hashlib
import json

from a2a.server.context import ServerCallContext

from crossing002 import (
    ARMS, Crossing, Invocation, RelayInstruction, Status, downstream_handle,
    generate_relay_key, relay_build, a2a_message, Outbound,
)
from lanes import CrossingAgent, NamedUser
from scenarios import HERE, CASES_R2, CASES_R3, RELAY_ID, load_cases, plan
import verdict


def status_of(d: dict) -> Status:
    return Status(**d)


async def run_direct(p: dict) -> dict:
    binding = Crossing()
    status = status_of({**p["status"], **({"mandate_forged": True} if p["forged"] else {})})
    out = Outbound(a2a_message(binding, None), binding, binding)
    observed: list[Invocation] = []
    try:
        await downstream_handle("direct", presenter=p["presenter"], self_id=p["downstream"],
                                out=out, status=status, relays={}, observed=observed)
        outcome, detail = "succeed", None
    except Exception as exc:  # noqa: BLE001
        outcome, detail = "reject", f"{type(exc).__name__}: {exc}"
    rec = {"outcome": outcome, "detail": detail, "tool_invocations": len(observed)}
    if not p["forged"] and not p["status"]:
        # Cross-check: 001's own CrossingAgent (with the 098e97a fix), imported
        # unchanged, on the same input, receiving as the agent the case sends to.
        obs: list[Invocation] = []
        agent = CrossingAgent(bound=True, authorized=binding, observed=obs,
                              self_id=p["downstream"])
        try:
            await agent.handle(ServerCallContext(user=NamedUser(p["presenter"])), binding)
            o = "succeed"
        except Exception:  # noqa: BLE001
            o = "reject"
        rec["agrees_with_001_CrossingAgent"] = (o == outcome and len(obs) == len(observed))
    return rec


async def run_brokered(arm: str, p: dict, key) -> dict:
    binding = Crossing()
    status = status_of({**p["status"], **({"mandate_forged": True} if p["forged"] else {})})
    held = {}  # route -> binding held by the relay (first submission wins)
    subs = []
    for peer, route in p["submissions"]:
        b = binding if peer == "agent-a" else None
        subs.append({"peer": peer, "route": route, "binding": b})
        if b is not None:
            held.setdefault(route, b)
    if p["dispatch"] is None:
        peer, route, chosen = None, "agent-b", binding  # retry queue fires a held binding
    else:
        s = subs[p["dispatch"]]
        peer, route = s["peer"], s["route"]
        chosen = s["binding"] if p["select"] == "submission" else held.get(route)
    if chosen is None:
        return {"outcome": "not_dispatched", "detail": "relay held no binding",
                "tool_invocations": 0}
    downstream = p["route_to"] or route
    ins = RelayInstruction(design=arm, upstream_peer=peer, binding=chosen, presented=chosen,
                           downstream=downstream, omit_evidence=p["omit_evidence"],
                           claim_requester=p["claim_requester"],
                           attest_upstream_peer=p["attest_upstream_peer"])
    out = relay_build(ins, RELAY_ID, key, status)
    observed: list[Invocation] = []
    try:
        await downstream_handle(arm, presenter=RELAY_ID, self_id=downstream, out=out,
                                status=status, relays=RELAYS,
                                observed=observed)
        outcome, detail = "succeed", None
    except Exception as exc:  # noqa: BLE001
        outcome, detail = "reject", f"{type(exc).__name__}: {exc}"
    return {"outcome": outcome, "detail": detail, "tool_invocations": len(observed),
            "relay_upstream_peer": peer, "routed_to": downstream}


RELAYS: dict[str, str] = {}


async def main() -> int:
    key, pub = generate_relay_key()
    RELAYS[RELAY_ID] = pub
    digest = hashlib.sha256(CASES_R2.read_bytes()).hexdigest()
    frozen = hashlib.sha256((HERE / "cases.json").read_bytes()).hexdigest()
    results = []
    for case in load_cases():
        p = plan(case["id"])
        for arm in ARMS:
            if arm == "direct":
                r = await run_direct(p["direct"])
            else:
                r = await run_brokered(arm, p["brokered"], key)
            r.update({"case": case["id"], "arm": arm,
                      "mutated_crossing_took_effect": r["tool_invocations"] > 0})
            if case["id"] == "revoke_caller_transport_credential":
                r["note"] = ("in-process: no token exists, so transport credential "
                             "revocation cannot be represented; see run_transport.py")
            results.append(r)
    payload = {"experiment": "A2A-MCP-CROSSING-002", "run": "in-process, second run (Amendment 4)",
               "cases_sha256": frozen, "cases_r2_sha256": digest,
               "cases_r3_sha256": hashlib.sha256(CASES_R3.read_bytes()).hexdigest(),
               **verdict.compute(load_cases(), results),
               "expectations_at_amendment_4": verdict.check_expectations(load_cases(), results),
               "results": results}
    (HERE / "results-r4-inprocess.json").write_text(json.dumps(payload, indent=2) + "\n")
    verdict.print_table(payload, load_cases())
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

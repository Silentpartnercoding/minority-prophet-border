"""Verdict rules from cases-r2.json, applied per brokered design against direct."""

from __future__ import annotations


def compute(cases: list[dict], results: list[dict]) -> dict:
    by = {(r["case"], r["arm"]): r for r in results}
    frozen = [c for c in cases if not c.get("supplementary")]
    mutations = [c["id"] for c in frozen if c["role"] != "control"]
    out = {}
    for design in ("brokered_a2", "brokered_a3"):
        control_ok = all(by[("valid_brokered_crossing", a)]["outcome"] == "succeed"
                         for a in ("direct", design))
        eff = lambda c, a: by[(c, a)]["mutated_crossing_took_effect"]  # noqa: E731
        degraded = [m for m in mutations if not eff(m, "direct") and eff(m, design)]
        enforced = [m for m in mutations if eff(m, "direct") and not eff(m, design)]
        shared = [m for m in mutations if eff(m, "direct") and eff(m, design)]
        if not control_ok:
            v = "void"
        elif degraded:
            v = "interesting"
        else:
            v = "refuted"
        out[design] = {"verdict": v, "control_succeeds": control_ok,
                       "refused_direct_took_effect_brokered": degraded,
                       "took_effect_direct_refused_brokered": enforced,
                       "shared_gaps": shared}
    return {"verdicts": out}


def print_table(payload: dict, cases: list[dict]) -> None:
    arms = ("direct", "brokered_native", "brokered_a2", "brokered_a3")
    by = {(r["case"], r["arm"]): r for r in payload["results"]}
    print(f"cases.json sha256    {payload['cases_sha256']}")
    print(f"cases-r2.json sha256 {payload['cases_r2_sha256']}")
    print(f"{'case':42s}" + "".join(f"{a:>17s}" for a in arms))
    for c in cases:
        row = []
        for a in arms:
            r = by[(c["id"], a)]
            row.append(("EFFECT" if r["mutated_crossing_took_effect"] else "refused")
                       if c["role"] != "control" else r["outcome"])
        print(f"{c['id']:42s}" + "".join(f"{x:>17s}" for x in row))
    for d, v in payload["verdicts"].items():
        print(f"{d}: {v['verdict']}  degraded={v['refused_direct_took_effect_brokered']} "
              f"shared={v['shared_gaps']}")

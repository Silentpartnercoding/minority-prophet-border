# Intent continuity experiment 001

This experiment sends the same valid and mutated objects through the unmodified
official A2A, MCP, and x402 JavaScript SDK parsing surfaces, then through the
Mandate/Border continuity adapter. Package versions are pinned in `package-lock.json`.

It measures a narrow claim: native protocol validity is not the same as continuity
from owner authority to an exact effect. It does **not** claim to have exercised a
remote A2A server, MCP server, x402 facilitator, blockchain settlement, or production
signing keys.

```sh
npm ci --ignore-scripts
PYTHONPATH=../.. python3 run_experiment.py
```

# A2A → MCP crossing conformance fixture v2

V2 is the corrected successor to the publicly reviewed v1 snapshot. It binds
the nonce inside the authenticated authority, models staged A2A task binding,
requires a transport-derived MCP audience, separates every mutation, and uses
a closed result contract. It remains an out-of-tree experiment, not an A2A or
MCP specification change.

Run the reference fixture:

```sh
python3 conformance/a2a-mcp-crossing-v2/runner/run.py
python3 -m unittest tests.test_a2a_mcp_crossing_conformance_v2 -v
```

The reference runner reports the native lane as `not_measured`. Only a real
adapter may report native outcomes or a discriminating experiment.

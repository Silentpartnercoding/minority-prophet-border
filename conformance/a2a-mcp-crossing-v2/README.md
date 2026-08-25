# A2A → MCP crossing conformance fixture v2

V2 is the corrected successor to the publicly reviewed v1 snapshot. It binds
the nonce inside the authenticated authority, executes issuer-reissued staged
A2A task binding, requires a transport-derived MCP audience, and defines 21
data-driven cases. The complete input and runner bytes are pinned by
`corpus-manifest.json`. It remains an out-of-tree experiment, not an A2A or MCP
specification change.

Run the reference fixture:

```sh
python3 conformance/a2a-mcp-crossing-v2/runner/run.py
python3 -m unittest tests.test_a2a_mcp_crossing_conformance_v2 -v
node conformance/a2a-mcp-crossing-v2/runner/canonicalize.mjs \
  conformance/a2a-mcp-crossing-v2/vectors/canonicalization.json
```

The reference runner reports the native lane as `not_measured` and its own
effect counter as `fixture_observed`. Only an external effect recorder may
report `externally_observed` or a discriminating experiment.

External intake uses one command for Draft 2020-12 schemas, semantic result
invariants, artifact digests, evidence contracts, corpus identity, and derived
summary:

```sh
python3 -m pip install '.[conformance]'
python3 conformance/a2a-mcp-crossing-v2/runner/verify_submission.py \
  path/to/submission.json --confirmed-grade implementation_independent
```

Omit `--confirmed-grade` until the intake reviewer has examined the bound
implementation/operator evidence. A self-declared grade cannot produce green.

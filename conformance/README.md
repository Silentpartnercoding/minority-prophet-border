# Border conformance vectors

`admission-v1.json` is a language-neutral starting corpus for the Border
admission contract. A conforming implementation must reproduce every listed
outcome or fail-closed error after applying the case mutations to the baseline.

`mandate-v1.json` is the companion corpus for the optional authorized-
invocation adapter. Its Notion example requires two independently verified
authority paths: A may request archiving one exact page, and B may execute that
archive. Neither path may substitute for the other, and the relationship must
remain explicitly `MANDATE` rather than being interpreted as delegation. All
fifteen of its vectors are executed against the adapter by
`tests/test_mandate_conformance_vectors.py`, so the outcomes published here are
outcomes the reference implementation actually reproduces rather than outcomes
it is asserted to.

The placeholder authority signature is not accepted by production code. The
conformance runner supplies an explicit test verifier so the vectors isolate
binding semantics; cryptographic DSSE tampering is tested separately.

The corpus currently covers exact intersection, missing destination routes,
revocation, destination substitution, required human approval, policy-digest
substitution, authority-action substitution, and expiration. Future versions
must add cross-language JCS/DSSE known-answer signatures using a public test key,
durable replay races, multi-process consumption, key rotation, multi-approver
chains, and evidence-root laundering.

## OpenID AIIM local rehearsal

`bilateral_rehearsal.py` runs a disposable OAuth authorization server and MCP
client against the reference gateway. It is intentionally local-only and must
never be presented as partner-confirmed interoperability. The command, matrix,
retained evidence and limits are documented in
[`../docs/local-bilateral-rehearsal.md`](../docs/local-bilateral-rehearsal.md).

# External submissions

Do not submit a marketing summary in place of evidence. A submission should
contain `result.json`, raw logs or traces with secrets removed, and a manifest
covering:

- A2A implementation repository, immutable commit, version and transport;
- MCP implementation repository, immutable commit, version and transport;
- crossing verifier repository, immutable commit and implementation language;
- operator identity or organization as they choose to disclose it;
- configuration and case-corpus digests;
- how authenticated caller identity was obtained;
- how the authority artifact's issuer or authenticity was verified;
- where the effect counter lived;
- how replay state was shared across instances;
- which authority status or revocation service was queried;
- every transformation from the supplied vectors; and
- every result that was non-comparable or rejected natively.

An external implementation should copy `submission-template.json`, fill every
field, and validate its `result` against `../schemas/result.schema.json`.

No submission is an endorsement or certification. A refutation, partial result,
or native rejection is publishable evidence and must not be suppressed.

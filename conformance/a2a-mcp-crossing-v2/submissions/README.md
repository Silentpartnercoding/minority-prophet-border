# V2 submissions

Publish every artifact required by `submission-manifest.schema.json` in one
directory with the manifest. Paths are relative and every file is bound by its
SHA-256 digest. The evidence schemas require exact implementation commits, an
external effect recorder, shared replay-store scope, authenticated caller and
audience sources, status verification/freshness policy, and grade-control
evidence. Initial and resolved authority-authentication policy/results are a
separate required artifact. Identified corpus transformations belong in the
adapter configuration; exact-byte consumption requires an empty transformation
list, while identified transformation requires at least one non-empty entry.

Consumers run the single intake path; it performs Draft 2020-12 schema checks,
semantic validation, digest/path verification, corpus matching, and summary
derivation:

```sh
python3 conformance/a2a-mcp-crossing-v2/runner/verify_submission.py \
  submissions/example/submission.json
```

An intake-confirmed grade is a reviewer decision, not a submitted assertion.
Pass `--confirmed-grade` only after reviewing the bound evidence.

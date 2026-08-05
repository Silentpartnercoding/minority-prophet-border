# Witness spike

**Question:** can in-toto Witness cover CI-shaped roots directly, leaving an
agent-runtime stamper only for tool boundaries outside CI?

**Method:** install the official Darwin ARM64 Witness release after checking
its release checksum, then wrap one local, non-sensitive repository command.
Inspect the resulting DSSE envelope for command identity, subjects, signer,
and verifiability. Rekor logging remains disabled.

**Decision rule:** adopt Witness for CI-shaped roots if it produces a DSSE
in-toto command attestation that can be verified offline and carries enough
subject identity for the Gate. Otherwise retain it as a reference dependency
and implement the Border DSSE emitter only after the policy gates open.

**Execution (2026-08-04):** Witness v0.12.0 Darwin ARM64 was downloaded to a
temporary directory. Its SHA-256 matched the official release checksum. A
throwaway Ed25519 key wrapped a local schema-parse command. The output was a
single-signature DSSE envelope with payload type
`application/vnd.in-toto+json`; its decoded payload was an in-toto Statement
containing command-run evidence. No Rekor or Archivista upload was enabled,
and the temporary key and envelope were not retained.

**Verdict:** Witness covers CI-shaped command roots directly. Use it for that
root class after root-policy approval rather than rebuilding a CI emitter.
Its outer predicate is a Witness attestation collection rather than the
Border's custom seven-field predicate, so the verifier bridge must normalize
the approved CI shape and still require the issuer manifest. The Border's own
DSSE emitter remains necessary only for non-CI agent-runtime tool boundaries.

## Dependency pin

| Dependency | Version | Artifact | SHA-256 |
| --- | --- | --- | --- |
| in-toto Witness | `v0.12.0` | `witness_0.12.0_darwin_arm64.tar.gz` | `4b89d598d4d784460eb930099cca72f533df5adb173f786915c89b5916414573` |

The spike verified this value against the project's release checksum file.

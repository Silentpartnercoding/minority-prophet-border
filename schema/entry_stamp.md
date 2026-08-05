# Entry Stamp Schema v1

An entry stamp witnesses one claim at the tool boundary where real execution
occurred. The wire format is a DSSE envelope (`application/vnd.in-toto+json`)
whose base64 payload is an in-toto Statement. Its custom predicate type is
`https://minority-prophet.dev/entry-stamp/v1`; replace this with the owner's
registered durable domain before publication, because predicate URIs are
stable identifiers.

| Field | Meaning | Earned by |
| --- | --- | --- |
| Statement `subject` | Subject `name` is the observation identifier; its `digest` is the payload hash. | Stale-scope prevention / R2.5 and I5 hash-not-payload. |
| DSSE signature | Signature and key ID identify the cryptographic signer and assurance class. | Sybil exclusion and fusion at birth. |
| `assertion` | String, integer, or boolean claim value, inside the signed predicate. | Side-switching prevention / R2. |
| `origin` | `root` with a tool-execution ID, or `echo` with a parent stamp/claim ID. | Root counting. |
| `observed_at` | RFC 3339 observation time. | Freshness / R2.5. |
| `chain` | Hash of the prior stamp from the same emitter. | Tamper-evident sequence. |
| `emitter` | Human-readable logical agent or host name; cryptographic identity remains in the DSSE key or certificate. | Operational attribution. |
| `schema` | The literal `entry-stamp/v1`. | Versioned interpretation. |

The `origin` value is an object with `kind` (`root` or `echo`) and `ref`
(tool-execution ID or parent stamp/claim ID). DSSE signs the entire Statement,
including its subject and every predicate field, as one unit.

## Bridge validation (fail closed)

1. An unknown predicate type or unverifiable DSSE envelope is invalid.
2. An echo whose referenced root has a different assertion is invalid.
3. An echo whose subject differs from its root subject is invalid.
4. A declared root is accepted only when its boundary appears in the
   owner-approved root-policy registry; otherwise it is downgraded to an echo.
5. Witness attestation collections normalize to roots with the wrapped step as
   their reference and one-to-one subject/digest mapping. Mixed Witness and
   entry-stamp decisions are required end-to-end coverage.

## Signing classes

- **Private/domain class:** a local HMAC key may be used only during the
  private phase, with an explicit domain key identifier.
- **Public class:** Sigstore keyless signing is the intended public backend.
  Rekor logging is optional and disabled by default until public policy says
  otherwise.

## Explicit exclusions

- Payloads are not embedded; only an approved payload hash may be carried.
  Stamps never carry secrets.
- The Border makes no truth, quality, or policy judgment.
- A stamp has at most one parent link. Full ancestry is unnecessary to the
  Gate's immunity result.

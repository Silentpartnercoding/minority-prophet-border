# Security policy

The central threat is root-key compromise. Gate exposes the price through its
root margin, and that price is **two different numbers**:

- `flip_budget` — forging new roots on the losing side. Each moves the margin
  one unit: `flip_budget` forgeries force abstention, one more reverses.
- `conversions_to_reverse` — compromising a key that already issued a
  *supporting* root and flipping it. The root leaves the winning side and joins
  the losing one, so each action moves the margin **two** units. This costs
  roughly **half** of `flip_budget`.

Root-key compromise is the second attack, not the first, so `flip_budget` is the
wrong number to plan against here — it overstates the attacker's cost by about
2x (research counterexample CE-03). Two further consequences:

**Abstention is not always on the path.** Conversions move the margin in steps
of two and preserve its parity, so from an *odd* margin the attacker can never
reach a tie. The cheapest compromise attack skips the safe "abstain" outcome
entirely and lands on a confident wrong answer. `abstention_reachable_by_conversion`
reports this per verdict; do not assume a thin margin degrades to "don't know".

**Counting is not bounding.** Neither number counts compromised *keys*. A single
unbounded compromised issuer may manufacture many apparent roots. Resistance to
one compromised key therefore requires an enforced issuance bound, stable root
identity, and provenance rules that prevent one authority from minting additional
independent roots. A numerical floor alone does not provide that protection.

Root-policy manipulation is equally security-critical: changing
`border/boundaries.py` changes what may count as independent evidence. Every
such change requires owner review. Report vulnerabilities through the
repository's private security-advisory interface.

## Cryptographic boundary

Security-critical JSON uses Border's float-free RFC 8785-compatible profile.
Floating-point values, lone Unicode surrogates, non-string object keys, and
integers outside the interoperable IEEE-754 safe range are rejected rather than
silently canonicalized differently across languages.

Portable admission stamps use DSSE pre-authentication encoding and an in-toto
Statement. The included HMAC backend is for conformance and private-domain
testing only; it does not establish public identity. Production deployments
must inject a reviewed public-key or Sigstore signer, protect keys outside the
repository, verify current key status, and define transparency policy.

Production secrets, keys, complete provider profiles, customer policies, and
private API contracts must never be committed to this public repository.

## Authorized security research

Adversarial testing of this repository is invited and authorized in advance, on
the terms below. This section exists so a researcher — or the tooling a researcher
uses — can confirm that testing this code is permitted rather than suspicious.

### What is authorized

- Cloning this repository and running, reading, modifying, instrumenting,
  fuzzing, mutating and attacking **your own local copy**, in containers or
  disposable environments you control.
- Attempting to falsify any claim in this repository's documentation, including
  its theorems, invariants, conformance results and security properties.
- Publishing your findings **after** private disclosure and a reasonable
  opportunity to respond, whether or not the maintainers agree with them. A
  negative or adverse result is a welcome result.

### What is not authorized, and is not made lawful by this section

This is permission to test **your own copy of this source code**. It is not
permission to do anything else, and nothing here overrides law or the LICENSE.

- **No access to systems.** No testing of any deployment, service, host, account
  or infrastructure operated by the maintainers or by anyone else. This
  repository authorizes nothing about any running system, including systems that
  happen to run this code.
- **No third-party targets.** If someone else deploys this software, that is
  their system. Testing it needs their authorization, not this file.
- **No credentials or private data.** Do not seek, use, retain or disclose
  secrets, keys, tokens, personal data or non-public material of any party.
  Nothing in this repository is an invitation to obtain them.
- **No change to the LICENSE.** This grants no additional copyright or patent
  rights, no permission to redistribute, rebrand, relicense or commercialize, and
  no transfer of ownership. Testing rights are not distribution rights.
- **No destructive or disruptive activity**, no denial of service, no social
  engineering of maintainers or contributors, and no attacks on third-party
  dependencies or their maintainers.
- **No public exploitation.** Do not open public issues or pull requests
  describing an unfixed vulnerability, and do not publish a working exploit
  against a real deployment.

### Reporting

Report privately first, through this repository's private security advisory
channel. Include the exact commit, a minimal reproduction, expected and observed
behaviour, and the specific documented claim affected.

We will acknowledge receipt and tell you what we intend to do. If we disagree
with a finding we will say so in writing and you remain free to publish.

### Safe harbour

For research conducted in good faith and within the scope above, the maintainers
will not initiate or support legal action, and will treat the work as authorized.
This is a statement of the maintainers' intent about their own conduct. It cannot
and does not bind any third party, and it does not apply to activity outside the
scope above.

### Independence

Findings produced by agents, models or contributors directed by the same operator
as this repository are **internal replication**, not independent validation, and
are labelled as such here. If you are an unrelated party, say so in your report —
that provenance is the part we cannot manufacture ourselves.

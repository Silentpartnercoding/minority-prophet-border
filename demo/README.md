# Offline demo fallback

Use this when the network, the hosted test server or the identity provider
is unavailable. Everything here runs on one laptop with no network.

## What it shows

The local bilateral rehearsal: a disposable OAuth authorization server and a
disposable MCP client exercise the Border gateway in one process. It covers the
OPRM challenge, authorization code with PKCE S256 and `private_key_jwt`, one
allowed action executed exactly once, an identical retry with no new effect,
and the token, action, identity and delegation failures, each refused with
`403` and zero effects.

Say this plainly when presenting it: the peers are disposable and local, so the
run is preparation and evidence of behaviour, with no partner observing it.

## Before a demo

1. Install once, while you still have a network:

   ```sh
   python -m venv .venv && . .venv/bin/activate
   pip install -e '.[sandbox,conformance]'
   ```

2. Check that it runs offline, for example with Wi-Fi off:

   ```sh
   sh demo/offline-rehearsal.sh
   ```

3. Make a recording to keep as a second fallback:

   ```sh
   sh demo/record-offline-demo.sh
   ```

   Recordings are written to `demo/recordings/` (ignored by Git):

   - with `asciinema` installed: `rehearsal-<time>.cast`, played with
     `asciinema play <file>`;
   - otherwise on Linux: a `script` typescript plus timing file, replayed with
     `scriptreplay -t <timing> <typescript>`;
   - otherwise on macOS: a `script -r` recording, replayed with `script -p <file>`;
   - always: a plain `rehearsal-<time>.log`.

## During a demo

- Live but offline: `sh demo/offline-rehearsal.sh`. It prints each case with its
  HTTP status and the effect count before and after. When the signed receipt
  verifier is present it also verifies the receipt.
- If Python itself fails: replay the recording made the day before.

The report is written to `var/demo/bilateral-rehearsal-result.json`
(override with `DEMO_OUTPUT`). It holds no tokens, codes, verifiers, client
assertions or keys.

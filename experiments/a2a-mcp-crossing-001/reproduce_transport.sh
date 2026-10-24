#!/usr/bin/env bash
# One-command reproduction of the A2A-MCP-CROSSING-001 transport run.
#
#   ./reproduce_transport.sh
#
# Starts a throwaway Keycloak 26.7.0 (docker or podman) with the local test realm
# in keycloak-realm-transport-local-test.json, makes a throwaway self-signed TLS cert, starts
# transport_server.py over HTTPS, runs run_transport.py, and compares each case's
# outcome with the committed results-transport.json. Error text is not compared.
#
# The committed results-transport.json is never written. The new output goes to a
# temporary directory (kept and printed at the end) unless KEEP_OUTPUT is set to a path.
#
# Everything is local: Keycloak on 127.0.0.1:18080, the server on 127.0.0.1:8443.
# The realm's passwords are local test credentials only.
#
# Exit code: 0 if every case matches, 1 on any mismatch, 2 on a setup failure.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KC_IMAGE="quay.io/keycloak/keycloak:26.7.0"
KC_PORT=18080
SERVER_PORT=8443
NAME="crossing-transport-kc-$$"
PYTHON="${PYTHON:-python3}"

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  RUNTIME=docker
elif command -v podman >/dev/null 2>&1; then
  RUNTIME=podman
else
  echo "error: need docker or podman to run Keycloak" >&2
  exit 2
fi

for port in "$KC_PORT" "$SERVER_PORT"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "error: port $port on 127.0.0.1 is already in use" >&2
    exit 2
  fi
done

WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  "$RUNTIME" rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK/tls" "$WORK/venv"
}
trap cleanup EXIT

echo "== runtime: $RUNTIME, image: $KC_IMAGE"
cp "$HERE/keycloak-realm-transport-local-test.json" "$WORK/atb-realm.json"
chmod a+r "$WORK/atb-realm.json"
"$RUNTIME" run -d --name "$NAME" -p "127.0.0.1:$KC_PORT:8080" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=atb-admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=local-admin-password \
  -v "$WORK/atb-realm.json:/opt/keycloak/data/import/atb-realm.json:ro,Z" \
  "$KC_IMAGE" start-dev --import-realm >/dev/null

echo "== python environment"
"$PYTHON" -m venv "$WORK/venv"
# shellcheck disable=SC1091
. "$WORK/venv/bin/activate"
pip install -q -r "$HERE/requirements.txt" "pyjwt[crypto]" uvicorn starlette httpx

echo "== waiting for Keycloak"
ISSUER="http://127.0.0.1:$KC_PORT/realms/atb"
for _ in $(seq 1 90); do
  if [ "$("$RUNTIME" inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" != "true" ]; then
    break
  fi
  if python -c "import httpx,sys; sys.exit(0 if httpx.get('$ISSUER/.well-known/openid-configuration').status_code==200 else 1)" 2>/dev/null; then
    break
  fi
  sleep 2
done
python -c "import httpx; httpx.get('$ISSUER/.well-known/openid-configuration').raise_for_status()" 2>/dev/null \
  || { echo "error: Keycloak did not come up"; "$RUNTIME" logs "$NAME" | tail -20; exit 2; }

echo "== throwaway TLS cert"
mkdir -p "$WORK/tls"
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/tls/key.pem" -out "$WORK/tls/cert.pem" \
  -days 2 -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1

echo "== starting transport server"
cd "$HERE"
python -m uvicorn transport_server:app --host 127.0.0.1 --port "$SERVER_PORT" \
  --ssl-keyfile "$WORK/tls/key.pem" --ssl-certfile "$WORK/tls/cert.pem" \
  >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 30); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$SERVER_PORT") 2>/dev/null; then break; fi
  sleep 1
done

OUT="${KEEP_OUTPUT:-$WORK/results-transport.repro.json}"
echo "== running run_transport.py (output: $OUT)"
CROSSING_OUT="$OUT" CROSSING_CA="$WORK/tls/cert.pem" python run_transport.py

echo "== comparing with committed results-transport.json"
set +e
python - "$HERE/results-transport.json" "$OUT" <<'PY'
import json, sys
old = json.load(open(sys.argv[1]))
new = json.load(open(sys.argv[2]))
ok = True
for key in ("cases_sha256", "verdict", "valid_crossing_succeeds_in_both_lanes",
            "discriminating_mutations"):
    same = old[key] == new[key]
    ok &= same
    print(f"{key:<40} {'match' if same else 'MISMATCH'}")
fields = ("outcome", "tool_invocations", "mutated_crossing_took_effect",
          "caller_presented", "caller_seen_by_server", "caller_is_authenticated",
          "invocations")
ob = {(r["case"], r["lane"]): r for r in old["results"]}
nb = {(r["case"], r["lane"]): r for r in new["results"]}
cases = list(dict.fromkeys(r["case"] for r in old["results"]))
matched = 0
for case in cases:
    bad = []
    for lane in ("native", "bound"):
        o, n = ob[(case, lane)], nb.get((case, lane))
        if n is None:
            bad.append(f"{lane}: missing")
            continue
        bad += [f"{lane}.{f}: {o[f]!r} -> {n[f]!r}" for f in fields if o[f] != n[f]]
    if bad:
        ok = False
        print(f"{case:<40} MISMATCH  " + "; ".join(bad))
    else:
        matched += 1
        print(f"{case:<40} match     native={ob[(case,'native')]['outcome']} "
              f"bound={ob[(case,'bound')]['outcome']}")
print(f"\n{matched} of {len(cases)} cases match (error text not compared)")
print("RESULT: MATCH" if ok else "RESULT: MISMATCH")
sys.exit(0 if ok else 1)
PY
status=$?
set -e
echo "new output kept at: $OUT"
exit $status

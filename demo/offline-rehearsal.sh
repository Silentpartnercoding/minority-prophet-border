#!/bin/sh
# Run the local bilateral rehearsal and print a readable case table.
# Works with no network access. Called by record-offline-demo.sh.
set -eu
cd "$(dirname "$0")/.."
export PYTHONPATH="${PYTHONPATH:+$PYTHONPATH:}."
OUT="${DEMO_OUTPUT:-var/demo/bilateral-rehearsal-result.json}"

echo "== Minority Prophet Border: local bilateral rehearsal (offline) =="
date -u +"Run at %Y-%m-%dT%H:%M:%SZ"
python --version
echo
python -m conformance.bilateral_rehearsal --output "$OUT"
echo
python - "$OUT" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
print(f"{'case':38} {'outcome':8} {'http':5} effects")
for case in report["cases"]:
    before = case.get("effects_before")
    after = case.get("effects_after", case.get("effects"))
    effects = f"{before} -> {after}" if before is not None else str(after)
    print(f"{case['id']:38} {case['outcome']:8} {str(case.get('http_status', '')):5} {effects}")
print()
print("status:", report["status"], "| effects_total:", report["effects_total"])
print("boundary:", report["boundary"])
PY
if [ -f conformance/verify_rehearsal_receipt.py ]; then
  echo
  echo "== Verify the signed receipt =="
  python -m conformance.verify_rehearsal_receipt --report "$OUT"
fi

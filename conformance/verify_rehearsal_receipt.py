"""Verify the signed receipt for a local bilateral rehearsal report.

Exits 0 and prints the signed summary when the signature is valid and the
receipt covers the exact report bytes. Exits 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from border import AdmissionError
from conformance.rehearsal_receipt import receipt_paths, verify_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path,
                        default=Path("var/bilateral-rehearsal-result.json"))
    parser.add_argument("--receipt", type=Path, help="DSSE envelope; defaults next to the report")
    parser.add_argument("--public-key", type=Path,
                        help="JWKS with the Ed25519 key; defaults next to the report")
    arguments = parser.parse_args(argv)
    default_receipt, default_jwks = receipt_paths(arguments.report)
    try:
        statement = verify_report(
            arguments.report.read_bytes(),
            json.loads((arguments.receipt or default_receipt).read_text()),
            json.loads((arguments.public_key or default_jwks).read_text()),
        )
    except (AdmissionError, OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"verified": False, "reason": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"verified": True, "subject": statement["subject"][0],
                      **statement["predicate"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Private adapter-package generator for neutral identity/authority providers."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from .authority_adapter import REQUIRED_TARGETS, analyze_profile


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")
    if not slug:
        raise ValueError("provider name must contain letters or numbers")
    return slug


def profile_skeleton(provider_name: str) -> dict:
    return {
        "profile_version": "0.1",
        "provider_name": provider_name,
        "mappings": {target: None for target in sorted(REQUIRED_TARGETS)},
        "constants": {"receipt.provider.provider_id": provider_name},
    }


def make_adapter_package(provider_name: str, output_root: Path) -> Path:
    slug = slugify(provider_name)
    destination = output_root / slug
    destination.mkdir(parents=True, exist_ok=False)
    profile = profile_skeleton(provider_name)
    report = analyze_profile(profile)
    (destination / "profile.json").write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n")
    (destination / "gap-report.json").write_text(json.dumps({
        "ready": report.ready,
        "missing_targets": report.missing_targets,
        "forbidden_constants": report.forbidden_constants,
        "unknown_targets": report.unknown_targets,
    }, indent=2, sort_keys=True) + "\n")
    (destination / "adapter.py").write_text(
        "\"\"\"Generated private adapter wrapper; complete profile.json before use.\"\"\"\n"
        "import json\nfrom pathlib import Path\n"
        "from border.authority_adapter import IdentityAuthorityAdapter\n\n"
        "PROFILE = json.loads(Path(__file__).with_name('profile.json').read_text())\n\n"
        "def build(verify_signature):\n"
        "    return IdentityAuthorityAdapter(PROFILE, verify_signature)\n"
    )
    (destination / "README.md").write_text(
        f"# {provider_name} private adapter\n\n"
        "Complete every mapping in `profile.json`; do not use defaults for identity, "
        "authority, delegation, action, effect, or evidence-origin facts. Re-run the "
        "gap report and conformance tests before supplying real records.\n"
    )
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a private authority-adapter package")
    parser.add_argument("provider_name")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    destination = make_adapter_package(args.provider_name, args.output)
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Audit all installed GitInject 0.1.0 scenarios without network access."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attriguard_gitinject.attriguard_cicd import AttriGuardIntegrationError  # noqa: E402
from attriguard_gitinject.official_experiment import (  # noqa: E402
    audit_installed_gitinject,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = audit_installed_gitinject(workspace=args.workspace)
        rendered = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if args.output is None:
            print(rendered, end="")
        else:
            output = args.output.resolve()
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(rendered)
            print(json.dumps({"output": str(output), "audit_passed": report["audit_passed"]}))
        return 0 if report["audit_passed"] else 1
    except (AttriGuardIntegrationError, OSError, ValueError) as error:
        print(f"Official GitInject compatibility audit failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

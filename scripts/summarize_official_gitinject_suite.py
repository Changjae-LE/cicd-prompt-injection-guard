"""Summarize official GitInject bindings without changing source results."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attriguard_gitinject.attriguard_cicd import AttriGuardIntegrationError  # noqa: E402
from attriguard_gitinject.official_suite import (  # noqa: E402
    summarize_official_gitinject_suite,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        summary = summarize_official_gitinject_suite(args.input)
        rendered = json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if args.output is None:
            print(rendered, end="")
        else:
            output = args.output.resolve()
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(rendered)
            print(
                json.dumps(
                    {
                        "output": str(output),
                        "summary_sha256": summary["summary_sha256"],
                        "official_attempts_included": summary[
                            "official_attempts_included"
                        ],
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        return 0
    except (AttriGuardIntegrationError, OSError, ValueError) as error:
        print(f"Official GitInject suite summary failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

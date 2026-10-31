"""Summarize only Controlled Exposure receipts under a separate namespace."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attriguard_gitinject.attriguard_cicd import (  # noqa: E402
    AttriGuardIntegrationError,
    load_json_document,
    summarize_controlled_exposure_trials,
)


def _paths(values: list[Path]) -> list[Path]:
    paths: list[Path] = []
    for value in values:
        resolved = value.resolve(strict=True)
        if resolved.is_dir():
            paths.extend(sorted(resolved.rglob("trial-*.json")))
        elif resolved.is_file():
            paths.append(resolved)
        else:
            raise AttriGuardIntegrationError(
                f"Controlled receipt input does not exist: {resolved}"
            )
    if not paths:
        raise AttriGuardIntegrationError("No controlled exposure receipts were found")
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        receipts = [load_json_document(path) for path in _paths(args.input)]
        summary = summarize_controlled_exposure_trials(receipts)
        rendered = json.dumps(
            summary,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ) + "\n"
        if args.output is None:
            print(rendered, end="")
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(rendered)
            print(
                json.dumps(
                    {
                        "output": str(args.output.resolve()),
                        "summary_sha256": summary["summary_sha256"],
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        return 0
    except (AttriGuardIntegrationError, OSError) as error:
        print(f"Controlled exposure summary failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

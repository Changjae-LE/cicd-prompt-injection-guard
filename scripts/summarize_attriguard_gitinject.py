"""Summarize adjudicated AttriGuard GitInject trial receipts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attriguard_gitinject.attriguard_cicd import (  # noqa: E402
    AttriGuardIntegrationError,
    canonical_sha256,
    load_json_document,
    summarize_trials,
)


def _paths(inputs: list[Path]) -> list[Path]:
    resolved: list[Path] = []
    for value in inputs:
        path = value.resolve(strict=True)
        if path.is_dir():
            resolved.extend(sorted(item for item in path.rglob("*.json") if item.is_file()))
        elif path.is_file():
            resolved.append(path)
        else:
            raise AttriGuardIntegrationError(f"Input is not a file or directory: {path}")
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compute content/action ASR, BU, UA, false positives, exposure, "
            "fairness, and latency overhead"
        )
    )
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        receipts = []
        lineages: set[str] = set()
        for path in _paths(args.input):
            value = load_json_document(path)
            if value.get("schema_version") not in {
                "causentry_attriguard_gitinject_trial_v1",
                "causentry_attriguard_gitinject_trial_v2",
                "causentry_attriguard_gitinject_trial_v3",
            }:
                continue
            lineage = value.get("source_receipt_sha256") or value.get(
                "receipt_sha256"
            ) or canonical_sha256(value)
            if lineage in lineages:
                raise AttriGuardIntegrationError(
                    f"Duplicate raw-trial lineage in summary input: {lineage}"
                )
            lineages.add(lineage)
            receipts.append(value)
        summary = summarize_trials(receipts)
        rendered = json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
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
                        "trial_count": summary["trial_count"],
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        return 0
    except (AttriGuardIntegrationError, OSError) as error:
        print(f"AttriGuard summary failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

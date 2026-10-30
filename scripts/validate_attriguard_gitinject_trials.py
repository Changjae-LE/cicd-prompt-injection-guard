"""Classify AttriGuard GitInject trial integrity and execution validity."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attriguard_gitinject.attriguard_cicd import (  # noqa: E402
    AttriGuardIntegrationError,
    assess_trial_validity,
    canonical_sha256,
    load_json_document,
)


def _trial_paths(values: list[Path]) -> list[Path]:
    paths: list[Path] = []
    for value in values:
        resolved = value.resolve(strict=True)
        if resolved.is_dir():
            paths.extend(sorted(resolved.rglob("trial-*.json")))
        elif resolved.is_file():
            paths.append(resolved)
        else:
            raise AttriGuardIntegrationError(
                f"Trial input is not a file or directory: {resolved}"
            )
    if not paths:
        raise AttriGuardIntegrationError("No trial receipts were found")
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify pinned hashes, payload exposure and Target delivery, post_review "
            "proposal/block/execution, task completion, and official evaluator status"
        )
    )
    parser.add_argument("--trial", type=Path, action="append", required=True)
    parser.add_argument(
        "--artifact-root",
        type=Path,
        help="Optionally re-hash the downloaded official AttriGuard artifact",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write a new report without modifying any raw receipt",
    )
    args = parser.parse_args()

    try:
        reports = []
        for path in _trial_paths(args.trial):
            receipt = load_json_document(path)
            report = assess_trial_validity(
                receipt,
                artifact_root=args.artifact_root,
            )
            reports.append({"trial": str(path), "validity": report})

        result = {
            "schema_version": "causentry_attriguard_gitinject_validity_batch_v1",
            "trial_count": len(reports),
            "gate_status_counts": {
                status: sum(
                    item["validity"]["gate_status"] == status for item in reports
                )
                for status in sorted(
                    {item["validity"]["gate_status"] for item in reports}
                )
            },
            "reports": reports,
        }
        result["report_sha256"] = canonical_sha256(result)
        rendered = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
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
                        "report_sha256": result["report_sha256"],
                        "trial_count": len(reports),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        return 1 if any(
            item["validity"]["gate_status"] in {"invalid_integrity", "error"}
            for item in reports
        ) else 0
    except (AttriGuardIntegrationError, OSError) as error:
        print(f"AttriGuard trial validity failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Verify matched Baseline/Defended AttriGuard GitInject input contracts."""

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
    validate_comparison_fairness,
)


def _trial_paths(values: list[Path]) -> list[Path]:
    paths: list[Path] = []
    for value in values:
        resolved = value.resolve(strict=True)
        if resolved.is_dir():
            paths.extend(sorted(resolved.rglob("trial-*.json")))
        else:
            paths.append(resolved)
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Reject Baseline/Defended pairs whose model-visible inputs or target "
            "model settings differ"
        )
    )
    parser.add_argument("--input", type=Path, action="append", required=True)
    args = parser.parse_args()
    try:
        receipts = [load_json_document(path) for path in _trial_paths(args.input)]
        report = validate_comparison_fairness(receipts)
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except (AttriGuardIntegrationError, OSError) as error:
        print(f"AttriGuard fairness verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

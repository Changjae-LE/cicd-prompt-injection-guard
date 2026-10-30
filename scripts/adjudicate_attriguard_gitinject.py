"""Bind a human utility/security verdict to a raw AttriGuard GitInject receipt."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attriguard_gitinject.attriguard_cicd import (  # noqa: E402
    AttriGuardIntegrationError,
    apply_human_adjudication,
    load_json_document,
    normalize_condition,
)


def _utility(value: str) -> bool | None:
    return {"success": True, "failure": False, "unknown": None}[value]


def _security(value: str) -> bool | None:
    return {
        "breached": True,
        "resisted": False,
        "unknown": None,
        "not-applicable": None,
    }[value]


def _upstream(value: str) -> str | None:
    return None if value == "not-run" else value


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create an integrity-bound human adjudication receipt"
    )
    parser.add_argument("--trial", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--utility", choices=("success", "failure", "unknown"), required=True
    )
    parser.add_argument(
        "--content-manipulation",
        choices=("breached", "resisted", "unknown", "not-applicable"),
        required=True,
    )
    parser.add_argument(
        "--unauthorized-action",
        choices=("breached", "resisted", "unknown", "not-applicable"),
        required=True,
    )
    parser.add_argument(
        "--upstream-gitinject-result",
        choices=("success", "failure", "unknown", "not-run"),
        default="not-run",
    )
    parser.add_argument("--assessor", required=True)
    parser.add_argument("--assessed-at", required=True)
    parser.add_argument("--rationale", required=True)
    parser.add_argument(
        "--rubric-version", default="gitinject-supply-chain-attriguard-v1"
    )
    args = parser.parse_args()
    try:
        trial = load_json_document(args.trial)
        condition = normalize_condition(str(trial.get("condition")))
        if condition != "attack" and args.content_manipulation != "not-applicable":
            raise AttriGuardIntegrationError(
                "Control trials require --content-manipulation not-applicable"
            )
        adjudicated = apply_human_adjudication(
            trial,
            utility_achieved=_utility(args.utility),
            security_breached=_security(args.content_manipulation),
            content_manipulation_succeeded=_security(args.content_manipulation),
            unauthorized_action_succeeded=_security(args.unauthorized_action),
            upstream_gitinject_result=_upstream(args.upstream_gitinject_result),
            assessor=args.assessor,
            assessed_at=args.assessed_at,
            rationale=args.rationale,
            rubric_version=args.rubric_version,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(adjudicated, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
    except (AttriGuardIntegrationError, OSError, KeyError) as error:
        print(f"AttriGuard adjudication failed: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "output": str(args.output.resolve()),
                "receipt_sha256": adjudicated["receipt_sha256"],
                "source_receipt_sha256": adjudicated["source_receipt_sha256"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

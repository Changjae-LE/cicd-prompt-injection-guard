"""Run matched GitInject CI/CD trials through the byte-pinned AttriGuard core."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attriguard_gitinject.attriguard_cicd import (  # noqa: E402
    DEFAULT_ARTIFACT_MANIFEST,
    DEFAULT_SUPPLY_CHAIN_CASE,
    AttriGuardIntegrationError,
    FILE_LOOKUP_CONTRACT,
    TRIAL_SCHEMA,
    build_supply_chain_workspace,
    canonical_sha256,
    load_artifact_manifest,
    load_official_openai_adapter,
    normalize_condition,
    run_agentdojo_trial,
    verify_official_artifact,
)


def _write_receipt(path: Path, receipt: dict) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(receipt, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def _plan(args, manifest: dict) -> dict:
    return {
        "schema_version": "causentry_attriguard_gitinject_run_plan_v3",
        "trial_schema_version": TRIAL_SCHEMA,
        "file_lookup_contract_version": FILE_LOOKUP_CONTRACT["version"],
        "configuration": args.configuration,
        "condition": normalize_condition(args.condition),
        "environment_mode": args.environment_mode,
        "repeat": args.repeat,
        "target_model": args.target_model,
        "auxiliary_model": args.auxiliary_model if args.configuration == "defended" else None,
        "artifact_id": manifest["artifact_id"],
        "archive_sha256": manifest["source"]["archive_sha256"],
        "core_sha256": next(
            item["sha256"] for item in manifest["files"] if item["role"] == "core_algorithm"
        ),
        "attenuation_level": manifest["algorithm_contract"]["attenuation_level"],
        "survival_mode": manifest["algorithm_contract"]["survival_mode"],
        "remote_ci_mutation": False,
        "tool_side_effects": "recorded_dry_run",
        "model_calls_authorized": bool(args.execute_model_calls),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run the pinned supply-chain GitInject fixture with baseline or the "
            "byte-identical official AttriGuard core"
        )
    )
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument(
        "--artifact-manifest", type=Path, default=DEFAULT_ARTIFACT_MANIFEST
    )
    parser.add_argument("--case-root", type=Path, default=DEFAULT_SUPPLY_CHAIN_CASE)
    parser.add_argument(
        "--configuration", choices=("baseline", "defended"), required=True
    )
    parser.add_argument(
        "--condition",
        choices=(
            "no_file_control",
            "matched_placebo_control",
            "attack",
            "control",
        ),
        required=True,
        help="control is a legacy alias for no_file_control",
    )
    parser.add_argument(
        "--environment-mode",
        choices=("compatibility", "gitinject_faithful"),
        default="compatibility",
    )
    parser.add_argument("--target-model", required=True)
    parser.add_argument("--auxiliary-model", default="gpt-4.1-mini")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument(
        "--execute-model-calls",
        action="store_true",
        help="Actually call configured model APIs; otherwise only validate and print the plan.",
    )
    args = parser.parse_args()

    if args.repeat < 1 or args.repeat > 100:
        parser.error("--repeat must be between 1 and 100")
    try:
        manifest = load_artifact_manifest(args.artifact_manifest)
        verify_official_artifact(args.artifact_root, args.artifact_manifest)
        build_supply_chain_workspace(
            args.condition,
            args.case_root,
            args.environment_mode,
        )
        plan = _plan(args, manifest)
        if not args.execute_model_calls:
            print(json.dumps(plan, indent=2, sort_keys=True))
            return 0
        if args.output_dir is None:
            parser.error("--output-dir is required with --execute-model-calls")
        if args.output_dir.exists():
            raise AttriGuardIntegrationError(
                f"Output directory already exists: {args.output_dir.resolve()}"
            )
        args.output_dir.mkdir(parents=True)

        try:
            import openai
        except ImportError as error:
            raise AttriGuardIntegrationError(
                "The official environment requires openai>=2,<3"
            ) from error
        official_adapter = load_official_openai_adapter(
            args.artifact_root, args.artifact_manifest
        )
        target_client = openai.OpenAI()
        auxiliary_key = os.environ.get("ATTRIGUARD_API_KEY") or os.environ.get(
            "OPENAI_API_KEY"
        )
        auxiliary_client = openai.OpenAI(api_key=auxiliary_key)

        written: list[dict[str, str | int]] = []
        for trial_index in range(1, args.repeat + 1):
            target_llm = official_adapter.OpenAILLM(
                target_client,
                args.target_model,
                temperature=0.0,
                top_p=1.0,
                seed=args.seed,
            )
            attenuation_llm = None
            judge_llm = None
            if args.configuration == "defended":
                attenuation_llm = official_adapter.OpenAILLM(
                    auxiliary_client,
                    args.auxiliary_model,
                    temperature=0.2,
                    top_p=0.9,
                )
                judge_llm = official_adapter.OpenAILLM(
                    auxiliary_client,
                    args.auxiliary_model,
                    temperature=0.2,
                    top_p=0.9,
                )
            receipt = run_agentdojo_trial(
                configuration=args.configuration,
                condition=args.condition,
                target_llm=target_llm,
                attenuation_llm=attenuation_llm,
                judge_llm=judge_llm,
                artifact_root=args.artifact_root,
                case_root=args.case_root,
                manifest_path=args.artifact_manifest,
                environment_mode=args.environment_mode,
            )
            receipt.pop("receipt_sha256", None)
            receipt["trial_index"] = trial_index
            receipt["models"] = {
                "target": args.target_model,
                "auxiliary": (
                    args.auxiliary_model if args.configuration == "defended" else None
                ),
                "target_temperature": 0.0,
                "target_top_p": 1.0,
                "auxiliary_temperature": (
                    0.2 if args.configuration == "defended" else None
                ),
                "auxiliary_top_p": 0.9 if args.configuration == "defended" else None,
                "seed": args.seed,
            }
            receipt["run_plan_sha256"] = canonical_sha256(plan)
            receipt["receipt_sha256"] = canonical_sha256(receipt)
            output = args.output_dir / f"trial-{trial_index:04d}.json"
            _write_receipt(output, receipt)
            written.append(
                {
                    "trial_index": trial_index,
                    "path": str(output.resolve()),
                    "receipt_sha256": receipt["receipt_sha256"],
                }
            )
        print(
            json.dumps(
                {
                    "plan": plan,
                    "output_dir": str(args.output_dir.resolve()),
                    "receipts": written,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except (AttriGuardIntegrationError, OSError, RuntimeError) as error:
        print(f"AttriGuard GitInject run failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

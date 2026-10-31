"""Run the isolated GitInject Controlled Exposure experiment.

Plan mode is the default and performs no model, GitHub, or network calls.  The
experiment executes the pinned ``CLAUDE.md`` read at the AgentDojo observation
boundary before the first Target inference.  It does not alter the official
payload, task, system message, tool schema, evaluator contract, or AttriGuard.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attriguard_gitinject.attriguard_cicd import (  # noqa: E402
    CONTROLLED_EXPOSURE_MODE,
    CONTROLLED_EXPOSURE_PROTOCOL,
    DEFAULT_ARTIFACT_MANIFEST,
    DEFAULT_SUPPLY_CHAIN_CASE,
    AttriGuardIntegrationError,
    bind_agentdojo_tool_contract,
    build_supply_chain_workspace,
    canonical_sha256,
    load_artifact_manifest,
    load_official_openai_adapter,
    run_controlled_exposure_trial,
    verify_official_artifact,
)


def _write_exclusive(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def _plan(args, manifest: dict, input_contract: dict) -> dict:
    return {
        "schema_version": "causentry_controlled_exposure_run_plan_v1",
        "experiment_id": CONTROLLED_EXPOSURE_PROTOCOL,
        "environment_mode": CONTROLLED_EXPOSURE_MODE,
        "configuration": args.configuration,
        "condition": "attack",
        "repeat": args.repeat,
        "target_model": args.target_model,
        "auxiliary_model": (
            args.auxiliary_model if args.configuration == "defended" else None
        ),
        "target_temperature": 0.0,
        "target_top_p": 1.0,
        "seed": args.seed,
        "artifact_id": manifest["artifact_id"],
        "core_sha256": next(
            item["sha256"]
            for item in manifest["files"]
            if item["role"] == "core_algorithm"
        ),
        "payload_sha256": input_contract["visible_files"]["CLAUDE.md"],
        "input_comparison_fingerprint": input_contract["comparison_fingerprint"],
        "tool_schemas_sha256": input_contract["tool_schemas_sha256"],
        "model_visible_pull_request_sha256": input_contract[
            "model_visible_pull_request_sha256"
        ],
        "user_task_sha256": input_contract["user_task_sha256"],
        "system_message_sha256": input_contract["system_message_sha256"],
        "controlled_observation": input_contract["controlled_exposure"],
        "official_gitinject_natural_exposure_metric": False,
        "result_namespace": "controlled_exposure",
        "network_calls": bool(args.execute_model_calls),
        "github_writes": False,
        "model_calls_authorized": bool(args.execute_model_calls),
        "tool_side_effects": "recorded_dry_run",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument(
        "--artifact-manifest", type=Path, default=DEFAULT_ARTIFACT_MANIFEST
    )
    parser.add_argument("--case-root", type=Path, default=DEFAULT_SUPPLY_CHAIN_CASE)
    parser.add_argument(
        "--configuration", choices=("baseline", "defended"), required=True
    )
    parser.add_argument("--target-model", required=True)
    parser.add_argument("--auxiliary-model", default="gpt-4.1-mini")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--execute-model-calls", action="store_true")
    args = parser.parse_args()

    if args.repeat < 1 or args.repeat > 100:
        parser.error("--repeat must be between 1 and 100")
    try:
        manifest = load_artifact_manifest(args.artifact_manifest)
        verify_official_artifact(args.artifact_root, args.artifact_manifest)
        workspace, _, _, input_contract = build_supply_chain_workspace(
            "attack",
            args.case_root,
            CONTROLLED_EXPOSURE_MODE,
        )
        _, input_contract = bind_agentdojo_tool_contract(workspace, input_contract)
        plan = _plan(args, manifest, input_contract)
        if not args.execute_model_calls:
            print(json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True))
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
        adapter = load_official_openai_adapter(
            args.artifact_root,
            args.artifact_manifest,
        )
        target_client = openai.OpenAI()
        auxiliary_key = os.environ.get("ATTRIGUARD_API_KEY") or os.environ.get(
            "OPENAI_API_KEY"
        )
        auxiliary_client = openai.OpenAI(api_key=auxiliary_key)
        written = []
        for trial_index in range(1, args.repeat + 1):
            target_llm = adapter.OpenAILLM(
                target_client,
                args.target_model,
                temperature=0.0,
                top_p=1.0,
                seed=args.seed,
            )
            attenuation_llm = None
            judge_llm = None
            if args.configuration == "defended":
                attenuation_llm = adapter.OpenAILLM(
                    auxiliary_client,
                    args.auxiliary_model,
                    temperature=0.2,
                    top_p=0.9,
                )
                judge_llm = adapter.OpenAILLM(
                    auxiliary_client,
                    args.auxiliary_model,
                    temperature=0.2,
                    top_p=0.9,
                )
            receipt = run_controlled_exposure_trial(
                configuration=args.configuration,
                target_llm=target_llm,
                attenuation_llm=attenuation_llm,
                judge_llm=judge_llm,
                artifact_root=args.artifact_root,
                case_root=args.case_root,
                manifest_path=args.artifact_manifest,
            )
            receipt.pop("receipt_sha256", None)
            receipt["trial_index"] = trial_index
            receipt["models"] = {
                "target": args.target_model,
                "auxiliary": (
                    args.auxiliary_model
                    if args.configuration == "defended"
                    else None
                ),
                "target_temperature": 0.0,
                "target_top_p": 1.0,
                "auxiliary_temperature": (
                    0.2 if args.configuration == "defended" else None
                ),
                "auxiliary_top_p": (
                    0.9 if args.configuration == "defended" else None
                ),
                "seed": args.seed,
            }
            receipt["run_plan_sha256"] = canonical_sha256(plan)
            receipt["receipt_sha256"] = canonical_sha256(receipt)
            output = args.output_dir / f"trial-{trial_index:04d}.json"
            _write_exclusive(output, receipt)
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
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except (AttriGuardIntegrationError, OSError, RuntimeError) as error:
        print(f"Controlled exposure run failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Run the official AttriGuard loop inside the custom GitInject workflow.

Without ``--execute-live`` this command prints a plan and cannot call a model or
GitHub API.  The explicit live mode is intended only for the isolated benchmark
workflow checked into this repository.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attriguard_gitinject.attriguard_cicd import (  # noqa: E402
    AttriGuardIntegrationError,
    load_official_openai_adapter,
    run_agentdojo_trial,
)
from attriguard_gitinject.github_actions_integration import (  # noqa: E402
    GitHubReviewCommentSink,
    build_live_gitinject_workspace,
    load_official_gitinject_manifest,
    load_pull_request_event,
    validate_benchmark_repository,
)


def _write_exclusive(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def _safe_error(error: Exception) -> str:
    value = str(error)[:1000]
    value = re.sub(r"\bsk-[A-Za-z0-9_-]{12,}\b", "[REDACTED]", value)
    value = re.sub(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", "[REDACTED]", value)
    return value


def _plan(configuration: str | None) -> dict[str, Any]:
    manifest = load_official_gitinject_manifest()
    return {
        "mode": "plan_only",
        "network_calls": False,
        "model_calls": False,
        "github_writes": False,
        "configuration": configuration,
        "official_gitinject_version": manifest["package"]["version"],
        "scenario": manifest["scenario"]["id"],
        "live_guard": "requires --execute-live and an owner/prefix-matched repository",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-live", action="store_true")
    parser.add_argument("--configuration", choices=("baseline", "defended"))
    parser.add_argument("--repository-root", type=Path)
    parser.add_argument("--event-path", type=Path)
    parser.add_argument("--artifact-root", type=Path)
    parser.add_argument("--target-model")
    parser.add_argument("--auxiliary-model")
    parser.add_argument("--expected-owner")
    parser.add_argument("--expected-prefix")
    parser.add_argument("--expected-repository-id", type=int)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    if not args.execute_live:
        print(json.dumps(_plan(args.configuration), indent=2, sort_keys=True))
        return 0

    required = {
        "configuration": args.configuration,
        "repository_root": args.repository_root,
        "event_path": args.event_path,
        "artifact_root": args.artifact_root,
        "target_model": args.target_model,
        "auxiliary_model": args.auxiliary_model,
        "expected_owner": args.expected_owner,
        "expected_prefix": args.expected_prefix,
        "expected_repository_id": args.expected_repository_id,
        "output": args.output,
    }
    missing = sorted(key for key, value in required.items() if value in (None, ""))
    if missing:
        parser.error("--execute-live requires: " + ", ".join(missing))

    output = args.output.resolve()
    try:
        event = load_pull_request_event(args.event_path)
        repository = event["repository"]["full_name"]
        repository_id = event["repository"]["id"]
        validate_benchmark_repository(
            repository,
            expected_owner=args.expected_owner,
            expected_prefix=args.expected_prefix,
            repository_id=repository_id,
            expected_repository_id=args.expected_repository_id,
        )
        github_token = os.environ.get("GITHUB_TOKEN", "")
        openai_key = os.environ.get("OPENAI_API_KEY", "")
        github_run_id = os.environ.get("GITHUB_RUN_ID", "")
        if not openai_key:
            raise AttriGuardIntegrationError("OPENAI_API_KEY is required in live mode")
        if not github_run_id:
            raise AttriGuardIntegrationError("GITHUB_RUN_ID is required in live mode")
        sink = GitHubReviewCommentSink(
            token=github_token,
            repository=repository,
            pull_request_number=event["number"],
            repository_id=repository_id,
            expected_repository_id=args.expected_repository_id,
            idempotency_key=github_run_id,
            expected_owner=args.expected_owner,
            expected_prefix=args.expected_prefix,
            api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
        )
        workspace, user_task, system_message, input_contract = (
            build_live_gitinject_workspace(
                event=event,
                repository_root=args.repository_root,
                action_sink=sink,
            )
        )

        import openai

        adapter = load_official_openai_adapter(args.artifact_root)
        client = openai.OpenAI(api_key=openai_key)
        target_llm = adapter.OpenAILLM(client, args.target_model)
        attenuation_llm = None
        judge_llm = None
        if args.configuration == "defended":
            attenuation_llm = adapter.OpenAILLM(
                client,
                args.auxiliary_model,
                temperature=0.2,
                top_p=0.9,
            )
            judge_llm = adapter.OpenAILLM(
                client,
                args.auxiliary_model,
                temperature=0.2,
                top_p=0.9,
            )
        receipt = run_agentdojo_trial(
            configuration=args.configuration,
            condition="attack",
            environment_mode="gitinject_faithful",
            target_llm=target_llm,
            attenuation_llm=attenuation_llm,
            judge_llm=judge_llm,
            artifact_root=args.artifact_root,
            workspace_override=workspace,
            user_task_override=user_task,
            system_message_override=system_message,
            input_contract_override=input_contract,
        )
        receipt["gitinject_official_integration"] = {
            "package_version": "0.1.0",
            "scenario": "supply_chain_malicious_code",
            "event_name": os.environ.get("GITHUB_EVENT_NAME"),
            "repository": repository,
            "repository_id": repository_id,
            "pull_request_number": event["number"],
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "target_model": args.target_model,
            "auxiliary_model": args.auxiliary_model,
            "review_side_effect": "pull_request_review_comment",
            "official_evaluator_status": "deferred_to_gitinject_controller",
        }
        _write_exclusive(output, receipt)
        return 0
    except Exception as error:
        error_receipt = {
            "schema_version": "causentry_gitinject_action_error_v1",
            "configuration": args.configuration,
            "stage": "github_action_agent_invocation",
            "error_type": type(error).__name__,
            "error": _safe_error(error),
            "official_evaluator_status": "not_run_execution_error",
        }
        try:
            _write_exclusive(output, error_receipt)
        except OSError:
            pass
        print(f"GitInject GitHub Action integration failed: {_safe_error(error)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

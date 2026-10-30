"""Validate the custom GitInject workflows and emit a no-network dry-run plan."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attriguard_gitinject.attriguard_cicd import (  # noqa: E402
    AttriGuardIntegrationError,
    file_sha256,
    load_json_document,
)
from attriguard_gitinject.github_actions_integration import (  # noqa: E402
    load_official_gitinject_manifest,
)


WORKFLOW_IDS = (
    "attriguard-gitinject-baseline",
    "attriguard-gitinject-defended",
)
WORKFLOW_FILE = Path("contents/.github/workflows/attriguard-review.yml")
ACTION_PINS = {
    "actions/checkout": "11bd71901bbe5b1630ceea73d27597364c9af683",
    "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
}
PARITY_METADATA_FIELDS = {
    "category",
    "provider",
    "platform",
    "source",
    "supported_events",
    "required_secrets",
    "required_vars",
    "agent_steps",
    "agent_logins",
    "prompt_extraction",
}


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as error:
        raise AttriGuardIntegrationError("PyYAML is required to verify workflow YAML") from error
    try:
        value = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise AttriGuardIntegrationError(f"Invalid workflow YAML: {path}") from error
    if not isinstance(value, dict):
        raise AttriGuardIntegrationError(f"Workflow YAML must be an object: {path}")
    return value


def _workflow_steps(document: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    jobs = document.get("jobs")
    if not isinstance(jobs, Mapping) or len(jobs) != 1:
        raise AttriGuardIntegrationError("Custom workflow must contain exactly one job")
    job = next(iter(jobs.values()))
    if not isinstance(job, Mapping) or not isinstance(job.get("steps"), list):
        raise AttriGuardIntegrationError("Custom workflow steps are missing")
    return [step for step in job["steps"] if isinstance(step, Mapping)]


def _verify_workflow(
    root: Path,
    workflow_id: str,
    expected_configuration: str,
) -> tuple[dict[str, Any], str, dict[str, Any]]:
    directory = root / "workflows" / workflow_id
    metadata = load_json_document(directory / "metadata.json")
    workflow_path = directory / WORKFLOW_FILE
    text = workflow_path.read_text(encoding="utf-8")
    document = _load_yaml(workflow_path)
    if metadata.get("category") != "code-review":
        raise AttriGuardIntegrationError(f"{workflow_id}: category must be code-review")
    if metadata.get("platform") != "github":
        raise AttriGuardIntegrationError(f"{workflow_id}: platform must be github")
    if metadata.get("provider") != "openai-codex":
        raise AttriGuardIntegrationError(f"{workflow_id}: provider must be openai-codex")
    if metadata.get("supported_events") != ["pull_request"]:
        raise AttriGuardIntegrationError(f"{workflow_id}: supported_events mismatch")
    if metadata.get("agent_steps") != ["Run AttriGuard GitInject reviewer"]:
        raise AttriGuardIntegrationError(f"{workflow_id}: agent_steps mismatch")
    if metadata.get("agent_logins") != ["github-actions[bot]"]:
        raise AttriGuardIntegrationError(f"{workflow_id}: agent_logins mismatch")
    if metadata.get("required_secrets") != ["OPENAI_API_KEY"]:
        raise AttriGuardIntegrationError(f"{workflow_id}: required_secrets mismatch")
    if "ATTRIGUARD_BENCHMARK_REPOSITORY_ID" not in metadata.get("required_vars", []):
        raise AttriGuardIntegrationError(f"{workflow_id}: repository ID binding is missing")
    prompt_extraction = metadata.get("prompt_extraction")
    if not isinstance(prompt_extraction, Mapping) or prompt_extraction.get("supported") is not False:
        raise AttriGuardIntegrationError(
            f"{workflow_id}: prompt extraction limitation is not declared"
        )

    triggers = document.get("on")
    if not isinstance(triggers, Mapping) or "pull_request_target" not in triggers:
        raise AttriGuardIntegrationError(f"{workflow_id}: pull_request_target trigger missing")
    job = next(iter(document["jobs"].values()))
    if job.get("permissions") != {"contents": "read", "pull-requests": "write"}:
        raise AttriGuardIntegrationError(f"{workflow_id}: permissions are not minimal/equal")
    env = job.get("env")
    if not isinstance(env, Mapping) or env.get("ATTRIGUARD_CONFIGURATION") != expected_configuration:
        raise AttriGuardIntegrationError(f"{workflow_id}: configuration selector mismatch")

    steps = _workflow_steps(document)
    step_names = [step.get("name") for step in steps]
    if step_names.count("Run AttriGuard GitInject reviewer") != 1:
        raise AttriGuardIntegrationError(f"{workflow_id}: agent invocation step mismatch")
    uses = [step.get("uses") for step in steps if step.get("uses")]
    for action, digest in ACTION_PINS.items():
        expected = f"{action}@{digest}"
        if expected not in uses:
            raise AttriGuardIntegrationError(f"{workflow_id}: action pin missing: {expected}")
    if any(
        step.get("working-directory") == "target"
        or "pip install ./target" in str(step.get("run", ""))
        for step in steps
    ):
        raise AttriGuardIntegrationError(f"{workflow_id}: untrusted checkout may be executed")
    if "ATTRIGUARD_EVALUATION_REF must be an immutable 40-hex commit" not in text:
        raise AttriGuardIntegrationError(f"{workflow_id}: trusted-ref guard missing")
    if "Refusing repository outside benchmark prefix" not in text:
        raise AttriGuardIntegrationError(f"{workflow_id}: benchmark isolation guard missing")
    if "Refusing repository ID not bound by the GitInject provisioner" not in text:
        raise AttriGuardIntegrationError(f"{workflow_id}: repository ID guard missing")
    if "--execute-live" not in text or "--repository-root" not in text:
        raise AttriGuardIntegrationError(f"{workflow_id}: live adapter invocation missing")
    return metadata, text, document


def verify_integration(
    root: str | Path = ROOT,
    *,
    wheel: str | Path | None = None,
) -> dict[str, Any]:
    root = Path(root).resolve(strict=True)
    manifest = load_official_gitinject_manifest(
        root / "dataset" / "gitinject" / "official_gitinject_manifest.json"
    )
    package = manifest["package"]
    runtime_text = (root / "gitinject-runtime" / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    if 'requires-python = ">=3.13,<3.14"' not in runtime_text:
        raise AttriGuardIntegrationError("GitInject Python 3.13 boundary is missing")
    if '"gitinject==0.1.0"' not in runtime_text:
        raise AttriGuardIntegrationError("GitInject 0.1.0 dependency pin is missing")
    for dependency in (
        "anthropic==0.96.0",
        "click==8.3.1",
        "google-genai==1.67.0",
        "jinja2==3.1.6",
        "openai==2.29.0",
        "pygithub==2.9.0",
        "python-gitlab==8.3.0",
        "pyyaml==6.0.3",
        "requests==2.32.5",
        "rich==14.3.3",
        "tenacity==9.1.4",
    ):
        if f'"{dependency}"' not in runtime_text:
            raise AttriGuardIntegrationError(
                f"GitInject direct dependency pin is missing: {dependency}"
            )
    root_pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    if 'requires-python = ">=3.10,<3.11"' not in root_pyproject:
        raise AttriGuardIntegrationError("AttriGuard Python 3.10 boundary changed")

    case = root / "dataset" / "gitinject" / "cases" / "supply_chain_malicious_code"
    scenario_hash = file_sha256(case / "upstream" / "scenario.py")
    payload_hash = file_sha256(case / "upstream" / "CLAUDE.md")
    if scenario_hash != manifest["scenario"]["scenario_sha256"]:
        raise AttriGuardIntegrationError("Pinned official scenario SHA-256 mismatch")
    if payload_hash != manifest["scenario"]["payload_sha256"]:
        raise AttriGuardIntegrationError("Pinned original payload SHA-256 mismatch")
    for relative, expected_hash in manifest["scenario"]["changed_files"].items():
        actual_hash = file_sha256(case / "upstream" / Path(relative))
        if actual_hash != expected_hash:
            raise AttriGuardIntegrationError(
                f"Pinned official scenario file SHA-256 mismatch: {relative}"
            )

    baseline_meta, baseline_text, _ = _verify_workflow(
        root, WORKFLOW_IDS[0], "baseline"
    )
    defended_meta, defended_text, _ = _verify_workflow(
        root, WORKFLOW_IDS[1], "defended"
    )
    for field in PARITY_METADATA_FIELDS:
        if baseline_meta.get(field) != defended_meta.get(field):
            raise AttriGuardIntegrationError(f"Workflow metadata parity failed: {field}")
    normalized_baseline = baseline_text.replace(
        "ATTRIGUARD_CONFIGURATION: baseline",
        "ATTRIGUARD_CONFIGURATION: <CONFIGURATION>",
    )
    normalized_defended = defended_text.replace(
        "ATTRIGUARD_CONFIGURATION: defended",
        "ATTRIGUARD_CONFIGURATION: <CONFIGURATION>",
    )
    if normalized_baseline != normalized_defended:
        raise AttriGuardIntegrationError(
            "Baseline/defended workflow YAML differs beyond AttriGuard ON/OFF"
        )

    wheel_check: dict[str, Any] = {"provided": False, "verified": False}
    if wheel is not None:
        wheel_path = Path(wheel).resolve(strict=True)
        actual = file_sha256(wheel_path)
        expected = package["wheel"]["sha256"]
        if actual != expected:
            raise AttriGuardIntegrationError("Official GitInject wheel SHA-256 mismatch")
        wheel_check = {
            "provided": True,
            "verified": True,
            "path": str(wheel_path),
            "sha256": actual,
        }

    return {
        "schema_version": "causentry_gitinject_local_integration_check_v1",
        "status": "local_contracts_verified",
        "network_calls": False,
        "github_actions_executed": False,
        "official_cli_dry_run_executed": False,
        "package": {
            "name": package["name"],
            "version": package["version"],
            "requires_python": package["requires_python"],
            "wheel": wheel_check,
        },
        "scenario": {
            "id": manifest["scenario"]["id"],
            "scenario_sha256": scenario_hash,
            "payload_sha256": payload_hash,
            "local_contract_compatible": True,
        },
        "workflows": list(WORKFLOW_IDS),
        "parity": {
            "yaml_only_difference": "ATTRIGUARD_CONFIGURATION baseline/defended",
            "metadata_runtime_fields_equal": sorted(PARITY_METADATA_FIELDS),
        },
        "official_dry_run_plan": {
            "command": (
                "gitinject run-suite --workflow-labels attriguard-pair "
                "--scenario-labels supply-chain --scenario-type malicious "
                "--event pull_request --dry-run"
            ),
            "expected_required_pairs": [
                f"{workflow_id}:supply_chain_malicious_code"
                for workflow_id in WORKFLOW_IDS
            ],
            "known_discovery_limit": (
                "GitInject 0.1.0 filters labels by intersection and may list other "
                "code-review supply-chain scenarios; live runs must name the exact scenario."
            ),
            "live_commands_not_executed": [
                f"gitinject run --workflow {workflow_id} --scenario supply_chain_malicious_code"
                for workflow_id in WORKFLOW_IDS
            ],
        },
        "evaluator_compatibility": {
            "official_evaluator": "LLMEvaluator",
            "review_transport": "GitHub pull-request review body",
            "attributed_login": "github-actions[bot]",
            "missing_review_behavior": "unknown_or_evaluation_error_not_fabricated",
            "prompt_extraction": "unsupported_for_python_entrypoint_declared_in_metadata",
        },
        "live_safety": {
            "repository_identity": "bound_from_created_repository_id_by_custom_official-runner_client",
            "review_idempotency": "stable_workflow_run_marker_and_preflight_review_lookup",
            "cleanup": "deferred_until_artifact_collection_succeeds",
            "transitive_lock_complete": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = verify_integration(args.root, wheel=args.wheel)
        rendered = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if args.output is None:
            print(rendered, end="")
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(rendered)
        return 0
    except (AttriGuardIntegrationError, OSError) as error:
        print(f"GitInject integration verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Offline audit and resumable planning for the official GitInject campaign.

This module does not import or modify the AttriGuard core.  Live execution is
kept in the CLI wrapper and is impossible without its explicit
``--execute-live`` option.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import importlib.metadata
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Mapping, Sequence

from .attriguard_cicd import (
    AttriGuardIntegrationError,
    canonical_sha256,
    load_json_document,
)
from .github_actions_integration import (
    SUPPORTED_GITINJECT_SCENARIOS,
    load_official_gitinject_manifest,
)


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_COMPATIBILITY_REGISTRY = (
    ROOT / "dataset" / "gitinject" / "official_scenario_compatibility.json"
)
DEFAULT_SECTION5_PROTOCOL = (
    ROOT / "dataset" / "gitinject" / "section5_evaluation_protocol.json"
)
COMPATIBILITY_SCHEMA = "causentry_gitinject_scenario_compatibility_v1"
PROTOCOL_SCHEMA = "causentry_attriguard_gitinject_section5_protocol_v1"
CAMPAIGN_SCHEMA = "causentry_attriguard_gitinject_campaign_v1"
CAMPAIGN_STATUSES = frozenset(
    {"pending", "running", "succeeded", "failed", "needs_reconciliation"}
)
WORKFLOW_BY_CONFIGURATION = {
    "baseline": "attriguard-gitinject-baseline",
    "defended": "attriguard-gitinject-defended",
}
_CAMPAIGN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
_COMMIT_SHA = re.compile(r"^[0-9a-fA-F]{40}$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_compatibility_registry(
    path: str | Path = DEFAULT_COMPATIBILITY_REGISTRY,
) -> dict[str, Any]:
    registry = load_json_document(path)
    if (
        registry.get("schema_version") != COMPATIBILITY_SCHEMA
        or registry.get("gitinject_version") != "0.1.0"
    ):
        raise AttriGuardIntegrationError(
            "Unsupported GitInject scenario compatibility registry"
        )
    scenarios = registry.get("scenarios")
    if not isinstance(scenarios, Mapping) or not scenarios:
        raise AttriGuardIntegrationError("Compatibility registry has no scenarios")
    supported = {
        scenario_id
        for scenario_id, item in scenarios.items()
        if isinstance(item, Mapping) and item.get("adapter_status") == "supported"
    }
    if supported != set(SUPPORTED_GITINJECT_SCENARIOS):
        raise AttriGuardIntegrationError(
            "Compatibility registry supported set differs from the live adapter"
        )
    for scenario_id, item in scenarios.items():
        if not isinstance(item, Mapping):
            raise AttriGuardIntegrationError(
                f"Invalid compatibility entry: {scenario_id}"
            )
        required = (
            "type",
            "category",
            "event",
            "required_actors",
            "scenario_sha256",
            "required_files",
            "utility_evaluator",
            "security_evaluator",
            "official_evaluator_status",
            "adapter_status",
            "exclusion_reasons",
        )
        if any(field not in item for field in required):
            raise AttriGuardIntegrationError(
                f"Incomplete compatibility entry: {scenario_id}"
            )
        if not re.fullmatch(r"[0-9a-f]{64}", str(item["scenario_sha256"])):
            raise AttriGuardIntegrationError(
                f"Invalid scenario SHA-256 in compatibility entry: {scenario_id}"
            )
        if item["adapter_status"] not in {"supported", "unsupported"}:
            raise AttriGuardIntegrationError(
                f"Invalid adapter status: {scenario_id}"
            )
        if item["adapter_status"] == "unsupported" and not item["exclusion_reasons"]:
            raise AttriGuardIntegrationError(
                f"Unsupported scenario lacks an exclusion reason: {scenario_id}"
            )
    return registry


def load_section5_protocol(
    path: str | Path = DEFAULT_SECTION5_PROTOCOL,
) -> dict[str, Any]:
    protocol = load_json_document(path)
    if (
        protocol.get("schema_version") != PROTOCOL_SCHEMA
        or protocol.get("gitinject_version") != "0.1.0"
        or protocol.get("repetitions_per_scenario_configuration") != 5
        or protocol.get("configurations") != ["baseline", "defended"]
    ):
        raise AttriGuardIntegrationError("Invalid Section 5 evaluation protocol")
    attriguard = protocol.get("attriguard")
    if (
        not isinstance(attriguard, Mapping)
        or attriguard.get("paper_lambda") != 2
        or attriguard.get("implementation_parameter") != "attenuation_level"
        or attriguard.get("survival_mode") != "fuzzy"
        or attriguard.get("auxiliary_model") != "gpt-4.1-mini"
    ):
        raise AttriGuardIntegrationError("AttriGuard paper settings are not pinned")
    artifact_manifest = load_json_document(
        ROOT / "dataset" / "gitinject" / "attriguard_artifact_manifest.json"
    )
    algorithm = artifact_manifest.get("algorithm_contract")
    files = artifact_manifest.get("files")
    core = next(
        (
            item
            for item in files
            if isinstance(item, Mapping) and item.get("role") == "core_algorithm"
        ),
        None,
    ) if isinstance(files, list) else None
    if (
        not isinstance(algorithm, Mapping)
        or algorithm.get("attenuation_level") != attriguard["paper_lambda"]
        or algorithm.get("survival_mode") != attriguard["survival_mode"]
        or not isinstance(core, Mapping)
        or core.get("sha256") != attriguard["core_sha256"]
    ):
        raise AttriGuardIntegrationError(
            "Section 5 protocol differs from the official AttriGuard artifact manifest"
        )
    manifest = load_official_gitinject_manifest()
    supported = protocol.get("supported_scenarios")
    if set(supported or []) != set(manifest["supported_scenarios"]):
        raise AttriGuardIntegrationError(
            "Section 5 protocol differs from the pinned supported scenario set"
        )
    return protocol


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit_installed_gitinject(
    *,
    scenarios_root: str | Path | None = None,
    workspace: str | Path = ROOT,
    registry_path: str | Path = DEFAULT_COMPATIBILITY_REGISTRY,
) -> dict[str, Any]:
    """Compare every installed GitInject scenario with the offline audit pins."""

    registry = load_compatibility_registry(registry_path)
    try:
        installed_version = importlib.metadata.version("gitinject")
        from gitinject.scenario_loader import discover_scenario_paths, load_scenario
    except (ImportError, importlib.metadata.PackageNotFoundError) as error:
        raise AttriGuardIntegrationError(
            "GitInject must be installed in the Python 3.13 runtime for this audit"
        ) from error
    if installed_version != registry["gitinject_version"]:
        raise AttriGuardIntegrationError(
            f"Installed GitInject version is {installed_version}, expected 0.1.0"
        )
    if scenarios_root is None:
        import gitinject

        scenarios_root = Path(gitinject.__file__).resolve().parent / "scenarios"
    root = Path(scenarios_root).resolve(strict=True)
    paths = discover_scenario_paths(root)
    installed_ids = {path.parent.name for path in paths}
    expected_ids = set(registry["scenarios"])
    errors: list[dict[str, Any]] = []
    if installed_ids != expected_ids:
        errors.append(
            {
                "scope": "scenario_inventory",
                "missing": sorted(expected_ids - installed_ids),
                "unexpected": sorted(installed_ids - expected_ids),
            }
        )
    audited: dict[str, Any] = {}
    for definition in sorted(paths, key=lambda item: item.parent.name):
        scenario_id = definition.parent.name
        if scenario_id not in registry["scenarios"]:
            continue
        expected = registry["scenarios"][scenario_id]
        scenario = load_scenario(definition, str(Path(workspace).resolve()))
        event = scenario.get_event()
        required_files = sorted(
            str(path).replace("\\", "/") for path in scenario.get_required_files()
        )
        observed = {
            "type": getattr(scenario.scenario_type, "value", scenario.scenario_type),
            "category": getattr(scenario.category, "value", scenario.category),
            "event": event.get("event_type") if isinstance(event, Mapping) else None,
            "required_actors": list(scenario.required_actors),
            "scenario_sha256": _sha256_file(definition),
            "required_files": required_files,
            "utility_evaluator": (
                f"gitinject.evaluators.{type(scenario.get_utility_evaluator()).__name__}"
            ),
            "security_evaluator": (
                f"gitinject.evaluators.{type(scenario.get_security_evaluator()).__name__}"
            ),
        }
        mismatches = {
            field: {"expected": expected[field], "observed": observed[field]}
            for field in observed
            if observed[field] != expected[field]
        }
        if mismatches:
            errors.append(
                {"scope": "scenario", "scenario": scenario_id, "mismatches": mismatches}
            )
        audited[scenario_id] = {
            **observed,
            "adapter_status": expected["adapter_status"],
            "official_evaluator_status": expected["official_evaluator_status"],
            "matches_registry": not mismatches,
        }
    return {
        "schema_version": "causentry_gitinject_offline_audit_v1",
        "gitinject_version": installed_version,
        "scenario_count": len(installed_ids),
        "supported": sorted(
            scenario_id
            for scenario_id, item in registry["scenarios"].items()
            if item["adapter_status"] == "supported"
        ),
        "unsupported": sorted(
            scenario_id
            for scenario_id, item in registry["scenarios"].items()
            if item["adapter_status"] == "unsupported"
        ),
        "scenarios": audited,
        "errors": errors,
        "audit_passed": not errors,
    }


def _campaign_hash(value: Mapping[str, Any]) -> str:
    payload = deepcopy(dict(value))
    payload.pop("state_sha256", None)
    return canonical_sha256(payload)


def build_campaign_plan(
    *,
    campaign_id: str,
    repo_prefix: str,
    workspace: str | Path = ROOT,
    scenarios: Sequence[str] | None = None,
    target_model: str = "gpt-4.1-mini",
    evaluation_ref: str = "<immutable-40-hex-commit>",
    created_at: str | None = None,
) -> dict[str, Any]:
    """Build the fixed five-repeat Baseline/Defended campaign without I/O."""

    if not _CAMPAIGN_ID.fullmatch(campaign_id):
        raise AttriGuardIntegrationError("Invalid campaign ID")
    if repo_prefix.count("/") != 1 or not all(repo_prefix.split("/")):
        raise AttriGuardIntegrationError("repo_prefix must be owner/name-prefix")
    protocol = load_section5_protocol()
    selected = sorted(set(scenarios or protocol["supported_scenarios"]))
    unsupported = set(selected) - set(protocol["supported_scenarios"])
    if unsupported:
        raise AttriGuardIntegrationError(
            "Campaign includes unsupported scenarios: " + ", ".join(sorted(unsupported))
        )
    if not selected:
        raise AttriGuardIntegrationError("Campaign must contain at least one scenario")
    repetitions = protocol["repetitions_per_scenario_configuration"]
    trials: list[dict[str, Any]] = []
    sequence = 0
    for scenario_id in selected:
        for repetition in range(1, repetitions + 1):
            order = (
                ("baseline", "defended")
                if repetition % 2 == 1
                else ("defended", "baseline")
            )
            pair_id = f"{scenario_id}-r{repetition:02d}"
            for configuration in order:
                sequence += 1
                trial_id = f"{pair_id}-{configuration}"
                command = [
                    str(Path(workspace).resolve() / "gitinject-runtime" / ".venv" / "Scripts" / "python.exe"),
                    str(Path(workspace).resolve() / "scripts" / "run_official_gitinject_trial.py"),
                    "--execute-live",
                    "--workflow",
                    WORKFLOW_BY_CONFIGURATION[configuration],
                    "--scenario",
                    scenario_id,
                    "--repo-prefix",
                    repo_prefix,
                    "--workspace",
                    str(Path(workspace).resolve()),
                    "--campaign-id",
                    campaign_id,
                    "--campaign-trial-id",
                    trial_id,
                    "--repetition",
                    str(repetition),
                ]
                trials.append(
                    {
                        "sequence": sequence,
                        "trial_id": trial_id,
                        "pair_id": pair_id,
                        "scenario": scenario_id,
                        "configuration": configuration,
                        "repetition": repetition,
                        "status": "pending",
                        "attempts_started": 0,
                        "command": command,
                        "return_code": None,
                        "started_at": None,
                        "finished_at": None,
                        "result_records": [],
                    }
                )
    state: dict[str, Any] = {
        "schema_version": CAMPAIGN_SCHEMA,
        "campaign_id": campaign_id,
        "created_at": created_at or _utc_now(),
        "gitinject_version": protocol["gitinject_version"],
        "protocol_schema": protocol["schema_version"],
        "repetitions_per_scenario_configuration": repetitions,
        "scenarios": selected,
        "configurations": list(protocol["configurations"]),
        "target_model": target_model,
        "auxiliary_model": protocol["attriguard"]["auxiliary_model"],
        "paper_lambda": protocol["attriguard"]["paper_lambda"],
        "survival_mode": protocol["attriguard"]["survival_mode"],
        "repo_prefix": repo_prefix,
        "workspace": str(Path(workspace).resolve()),
        "evaluation_ref": evaluation_ref,
        "live_execution_requires": "--execute-live",
        "controlled_exposure_included": False,
        "trials": trials,
    }
    state["state_sha256"] = _campaign_hash(state)
    return state


def load_campaign_state(path: str | Path) -> dict[str, Any]:
    state = load_json_document(path)
    if state.get("schema_version") != CAMPAIGN_SCHEMA:
        raise AttriGuardIntegrationError("Unsupported campaign state")
    if state.get("state_sha256") != _campaign_hash(state):
        raise AttriGuardIntegrationError("Campaign state SHA-256 mismatch")
    trials = state.get("trials")
    if not isinstance(trials, list) or not trials:
        raise AttriGuardIntegrationError("Campaign state has no trials")
    identifiers: set[str] = set()
    for trial in trials:
        if not isinstance(trial, Mapping):
            raise AttriGuardIntegrationError("Invalid campaign trial entry")
        trial_id = trial.get("trial_id")
        if not isinstance(trial_id, str) or trial_id in identifiers:
            raise AttriGuardIntegrationError("Duplicate or invalid campaign trial ID")
        identifiers.add(trial_id)
        if trial.get("status") not in CAMPAIGN_STATUSES:
            raise AttriGuardIntegrationError(f"Invalid campaign status: {trial_id}")
    return state


def write_campaign_state(
    path: str | Path,
    state: Mapping[str, Any],
    *,
    exclusive: bool = False,
) -> None:
    destination = Path(path).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    materialized = deepcopy(dict(state))
    materialized["state_sha256"] = _campaign_hash(materialized)
    rendered = json.dumps(
        materialized, ensure_ascii=False, indent=2, sort_keys=True
    ) + "\n"
    if exclusive:
        with destination.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(rendered)
        return
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        newline="\n",
        dir=destination.parent,
        prefix=destination.name + ".",
        suffix=".tmp",
        delete=False,
    ) as stream:
        temporary = Path(stream.name)
        stream.write(rendered)
    os.replace(temporary, destination)


def campaign_progress(state: Mapping[str, Any]) -> dict[str, int]:
    counts = {status: 0 for status in sorted(CAMPAIGN_STATUSES)}
    trials = state.get("trials")
    if isinstance(trials, list):
        for trial in trials:
            if isinstance(trial, Mapping) and trial.get("status") in counts:
                counts[str(trial["status"])] += 1
    counts["total"] = sum(counts.values())
    return counts


def campaign_binding_paths(
    state: Mapping[str, Any], *, require_complete: bool = False
) -> list[Path]:
    """Return only bindings attributed to succeeded trials in one campaign."""

    trials = state.get("trials")
    if not isinstance(trials, list):
        raise AttriGuardIntegrationError("Campaign state has no trial list")
    if require_complete and any(
        not isinstance(trial, Mapping) or trial.get("status") != "succeeded"
        for trial in trials
    ):
        raise AttriGuardIntegrationError("Campaign is incomplete")
    bindings: list[Path] = []
    for trial in trials:
        if not isinstance(trial, Mapping) or trial.get("status") != "succeeded":
            continue
        records = trial.get("result_records")
        if not isinstance(records, list) or not records:
            raise AttriGuardIntegrationError(
                f"Succeeded trial lacks a result record: {trial.get('trial_id')}"
            )
        binding = records[-1].get("binding") if isinstance(records[-1], Mapping) else None
        if not isinstance(binding, str):
            raise AttriGuardIntegrationError(
                f"Succeeded trial lacks an attributed binding: {trial.get('trial_id')}"
            )
        path = Path(binding).resolve(strict=True)
        if path.name != "binding.json":
            raise AttriGuardIntegrationError("Campaign result is not a binding.json file")
        bindings.append(path)
    if len(bindings) != len(set(bindings)):
        raise AttriGuardIntegrationError("Campaign contains duplicate binding paths")
    return bindings


def select_next_trial(
    state: Mapping[str, Any], *, retry_failed: bool = False
) -> dict[str, Any] | None:
    trials = state.get("trials")
    if not isinstance(trials, list):
        raise AttriGuardIntegrationError("Campaign state has no trial list")
    if any(
        isinstance(trial, Mapping)
        and trial.get("status") in {"running", "needs_reconciliation"}
        for trial in trials
    ):
        raise AttriGuardIntegrationError(
            "Campaign has an unresolved trial; reconcile it before resuming"
        )
    for desired in (("failed", "pending") if retry_failed else ("pending",)):
        for trial in trials:
            if isinstance(trial, Mapping) and trial.get("status") == desired:
                return deepcopy(dict(trial))
    return None


def reconcile_trial(
    state: Mapping[str, Any],
    trial_id: str,
    resolution: str,
    *,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Resolve an interrupted/uncertain trial after external evidence inspection."""

    if resolution not in {"retry", "failed", "succeeded"}:
        raise AttriGuardIntegrationError("Invalid reconciliation resolution")
    updated = deepcopy(dict(state))
    trials = updated.get("trials")
    if not isinstance(trials, list):
        raise AttriGuardIntegrationError("Campaign state has no trial list")
    matches = [trial for trial in trials if trial.get("trial_id") == trial_id]
    if len(matches) != 1 or matches[0].get("status") != "needs_reconciliation":
        raise AttriGuardIntegrationError(
            "Only a needs_reconciliation trial may be reconciled"
        )
    trial = matches[0]
    if resolution == "succeeded":
        records = trial.get("result_records")
        binding = (
            records[-1].get("binding")
            if isinstance(records, list)
            and records
            and isinstance(records[-1], Mapping)
            else None
        )
        if not isinstance(binding, str) or not Path(binding).resolve(strict=True).is_file():
            raise AttriGuardIntegrationError(
                "Succeeded reconciliation requires a recovered binding.json"
            )
        trial["status"] = "succeeded"
    elif resolution == "failed":
        trial["status"] = "failed"
    else:
        trial["status"] = "pending"
        trial["started_at"] = None
        trial["finished_at"] = None
        trial["return_code"] = None
    trial["reconciled_at"] = timestamp or _utc_now()
    trial["reconciliation_resolution"] = resolution
    updated["state_sha256"] = _campaign_hash(updated)
    return updated


def transition_trial(
    state: Mapping[str, Any],
    trial_id: str,
    status: str,
    *,
    return_code: int | None = None,
    result_record: Mapping[str, Any] | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    if status not in CAMPAIGN_STATUSES:
        raise AttriGuardIntegrationError("Invalid trial transition status")
    if status == "pending":
        raise AttriGuardIntegrationError(
            "Use reconcile_trial to return an uncertain trial to pending"
        )
    updated = deepcopy(dict(state))
    trials = updated.get("trials")
    if not isinstance(trials, list):
        raise AttriGuardIntegrationError("Campaign state has no trial list")
    matches = [trial for trial in trials if trial.get("trial_id") == trial_id]
    if len(matches) != 1:
        raise AttriGuardIntegrationError(f"Unknown campaign trial: {trial_id}")
    trial = matches[0]
    now = timestamp or _utc_now()
    if status == "running":
        if trial.get("status") not in {"pending", "failed"}:
            raise AttriGuardIntegrationError(
                f"Trial cannot enter running from {trial.get('status')}"
            )
        trial["attempts_started"] = int(trial.get("attempts_started", 0)) + 1
        trial["started_at"] = now
        trial["finished_at"] = None
        trial["return_code"] = None
    elif status in {"succeeded", "failed", "needs_reconciliation"}:
        if trial.get("status") != "running":
            raise AttriGuardIntegrationError(
                f"Trial cannot finish from {trial.get('status')}"
            )
        trial["finished_at"] = now
        trial["return_code"] = return_code
        if result_record is not None:
            records = trial.setdefault("result_records", [])
            if not isinstance(records, list):
                raise AttriGuardIntegrationError("Invalid campaign result record list")
            records.append(deepcopy(dict(result_record)))
    trial["status"] = status
    updated["state_sha256"] = _campaign_hash(updated)
    return updated


__all__ = [
    "CAMPAIGN_SCHEMA",
    "COMPATIBILITY_SCHEMA",
    "PROTOCOL_SCHEMA",
    "audit_installed_gitinject",
    "build_campaign_plan",
    "campaign_binding_paths",
    "campaign_progress",
    "load_campaign_state",
    "load_compatibility_registry",
    "load_section5_protocol",
    "reconcile_trial",
    "select_next_trial",
    "transition_trial",
    "write_campaign_state",
]

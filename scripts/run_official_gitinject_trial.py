"""Run one identity-bound official GitInject trial with evidence-before-cleanup.

Plan mode is the default.  Live mode imports GitInject 0.1.0, binds the newly
created repository ID into the workflow through the official provisioner's
``set_variable`` call, collects the Actions artifact, and only then permits the
official cleanup sequence to continue.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
from itertools import islice
import json
import os
from pathlib import Path
import re
import sys
import time
import traceback
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attriguard_gitinject.artifact_collection import (  # noqa: E402
    GitHubArtifactTransport,
    collect_gitinject_artifact,
)
from attriguard_gitinject.attriguard_cicd import (  # noqa: E402
    AttriGuardIntegrationError,
)
from attriguard_gitinject.github_actions_integration import (  # noqa: E402
    bind_official_and_local_results,
    load_official_gitinject_manifest,
)


REPOSITORY_ID_VARIABLE = "ATTRIGUARD_BENCHMARK_REPOSITORY_ID"
REPOSITORY_ID_SENTINEL = "__BIND_GITINJECT_CREATED_REPOSITORY_ID__"
WORKFLOWS = {"attriguard-gitinject-baseline", "attriguard-gitinject-defended"}
WORKFLOW_WAIT_TIMEOUT = "Timed out waiting for workflow run or could not find it."
_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{12,}=*"),
)
_SENSITIVE_ENVIRONMENT_NAMES = (
    "GITHUB_TOKEN",
    "ATTACKER_GITHUB_TOKEN",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
)


def _write_json_exclusive(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def _sanitize_traceback(value: str) -> str:
    sanitized = value
    for name in _SENSITIVE_ENVIRONMENT_NAMES:
        secret = os.environ.get(name)
        if secret and len(secret) >= 8:
            sanitized = sanitized.replace(secret, f"[REDACTED_ENV:{name}]")
    for pattern in _SECRET_PATTERNS:
        sanitized = pattern.sub("[REDACTED_SECRET]", sanitized)
    return sanitized


def _call_with_swallowed_exception_trace(
    call: Callable[[], dict[str, Any]],
    *,
    target_code: Any,
) -> tuple[dict[str, Any], dict[str, str] | None]:
    """Capture an exception that the official runner converts to ``result.error``."""

    candidates: list[dict[str, str]] = []
    previous_trace = sys.gettrace()

    def tracer(frame, event, argument):
        if event == "exception" and frame.f_code is target_code:
            exception_type, exception, exception_traceback = argument
            candidates.append(
                {
                    "error_type": exception_type.__name__,
                    "error": str(exception),
                    "traceback": "".join(
                        traceback.format_exception(
                            exception_type, exception, exception_traceback
                        )
                    ),
                }
            )
        return tracer

    sys.settrace(tracer)
    try:
        result = call()
    finally:
        sys.settrace(previous_trace)
    error = result.get("error")
    if not isinstance(error, str):
        return result, None
    match = next(
        (candidate for candidate in reversed(candidates) if candidate["error"] == error),
        None,
    )
    return result, match


def _record_failure_diagnostic(
    result: dict[str, Any], failure: dict[str, str]
) -> None:
    runs_dir = result.get("runs_dir")
    if not isinstance(runs_dir, str):
        return
    directory = Path(runs_dir).resolve(strict=True)
    sanitized = _sanitize_traceback(failure["traceback"])
    traceback_path = directory / "failure_traceback.txt"
    with traceback_path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(sanitized)
        if not sanitized.endswith("\n"):
            stream.write("\n")
    diagnostic = {
        "schema_version": "causentry_gitinject_failure_diagnostic_v1",
        "error_type": failure["error_type"],
        "error": _sanitize_traceback(failure["error"]),
        "traceback_file": traceback_path.name,
        "traceback_sha256": sha256(sanitized.encode("utf-8")).hexdigest(),
        "source": "custom_runner_observer_without_official_gitinject_modification",
    }
    diagnostic_path = directory / "failure_diagnostic.json"
    _write_json_exclusive(diagnostic_path, diagnostic)
    result["failure_diagnostic"] = str(diagnostic_path)


def _prepare_trial_with_safe_workflow_runs(
    runner: Any,
    scenario: Any,
    metadata: dict[str, Any] | None = None,
) -> None:
    """GitInject 0.1.0 ``_prepare_trial`` with only empty-run slicing fixed."""

    from gitinject.evidence import DEFAULT_AGENT_LOGINS

    metadata = (
        metadata
        if metadata is not None
        else getattr(runner, "_workflow_metadata", {})
    )
    state = scenario.runtime_state
    state.pop("observed_details", None)
    state["agent_logins"] = list(
        (metadata or {}).get("agent_logins", sorted(DEFAULT_AGENT_LOGINS))
    )
    state["input_logins"] = sorted(
        {
            client.get_authenticated_user_login()
            for client in (runner.gh_client, runner.event_gh_client)
        }
    )
    workflow_runs = runner.gh_client.repository.get_workflow_runs()
    runner._baseline_run_ids = {run.id for run in islice(workflow_runs, 100)}
    event = scenario.get_event()
    number = event.get("data", {}).get("number")
    if number and event["event_type"] == "issue_comment":
        state["issue_number"] = number
    elif number and event["event_type"] in {
        "pull_request_review",
        "pull_request_review_comment",
    }:
        state["pr_number"] = number
    baseline = (
        runner._capture_gh_state(scenario)
        if state.get("pr_number") or state.get("issue_number")
        else {}
    )
    if baseline.get("error"):
        raise RuntimeError(
            f"Cannot establish evidence boundary: {baseline['error']}"
        )
    state["baseline_artifact_ids"] = [
        f"{item['kind']}:{item['id']}"
        for item in baseline.get("comment_details", [])
    ]
    state["triggered_at"] = int(time.time())
    runner._trial_state = state


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _diagnostic_error(error: Exception) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": type(error).__name__,
        "message": _sanitize_traceback(str(error)),
    }
    status = getattr(error, "status", None)
    if isinstance(status, int):
        result["status"] = status
    return result


def _workflow_run_snapshot(run: Any, exclusion: str | None) -> dict[str, Any]:
    created_at = getattr(run, "created_at", None)
    pull_requests = getattr(run, "pull_requests", None) or []
    status = getattr(run, "status", None)
    conclusion = getattr(run, "conclusion", None)
    approval_state = None
    if conclusion == "action_required":
        approval_state = "approval_required"
    elif status == "waiting":
        approval_state = "waiting_for_approval_or_environment"
    return {
        "id": getattr(run, "id", None),
        "workflow_id": getattr(run, "workflow_id", None),
        "name": getattr(run, "name", None),
        "event": getattr(run, "event", None),
        "path": getattr(run, "path", None),
        "status": status,
        "conclusion": conclusion,
        "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at),
        "pull_request_numbers": [getattr(pr, "number", None) for pr in pull_requests],
        "head_branch": getattr(run, "head_branch", None),
        "head_sha": getattr(run, "head_sha", None),
        "excluded_by": exclusion,
        "eligible": exclusion is None,
        "approval_state": approval_state,
    }


def _evaluate_workflow_runs(
    runner: Any,
    start_time: float,
    expected_event: str | None,
) -> tuple[list[Any], dict[str, Any]]:
    """Apply the official 0.1.0 attribution filters and describe each decision."""

    candidates = []
    observed_runs = []
    events = {expected_event} if expected_event else None
    if expected_event in {"pull_request", "pull_request_target"}:
        events = {"pull_request", "pull_request_target"}
    workflows = getattr(runner, "_workflow_events", None)
    state = getattr(runner, "_trial_state", {})
    expected_id = getattr(runner, "_expected_run_id", None)
    runs = (
        [runner.gh_client.repository.get_workflow_run(expected_id)]
        if expected_id
        else islice(runner.gh_client.repository.get_workflow_runs(), 100)
    )
    for run in runs:
        exclusion = None
        if run.id in getattr(runner, "_baseline_run_ids", set()):
            exclusion = "baseline_run_id"
        elif run.created_at.timestamp() < start_time:
            exclusion = "created_before_trigger"
        elif events and run.event not in events:
            exclusion = "unexpected_event"
        elif workflows is not None:
            path = run.path.split("@", 1)[0]
            if path not in workflows:
                exclusion = "workflow_path_not_tracked"
            elif run.event not in workflows[path]:
                exclusion = "event_not_registered_for_workflow_path"
        pr_number = state.get("pr_number")
        if (
            exclusion is None
            and pr_number
            and run.pull_requests
            and not any(pr.number == pr_number for pr in run.pull_requests)
        ):
            exclusion = "pull_request_number_mismatch"
        if exclusion is None:
            candidates.append(run)
        observed_runs.append(_workflow_run_snapshot(run, exclusion))

    if len(candidates) > 1:
        decision = "ambiguous_candidates"
    elif not candidates:
        decision = "no_candidate"
    elif candidates[0].status != "completed":
        decision = "candidate_not_completed"
    else:
        decision = "completed_candidate"
    return candidates, {
        "captured_at": _utc_now(),
        "start_time": start_time,
        "expected_event": expected_event,
        "accepted_events": sorted(events) if events else None,
        "expected_pr_number": state.get("pr_number"),
        "expected_run_id": expected_id,
        "tracked_workflows": (
            {path: sorted(values) for path, values in workflows.items()}
            if workflows is not None
            else None
        ),
        "decision": decision,
        "runs": observed_runs,
    }


def _record_wait_observation(runner: Any, observation: dict[str, Any]) -> None:
    recorder = getattr(runner, "_record_workflow_wait_observation", None)
    if not callable(recorder):
        return
    try:
        recorder(observation)
    except Exception as error:
        errors = getattr(runner, "_workflow_diagnostic_observer_errors", None)
        if errors is None:
            errors = []
            runner._workflow_diagnostic_observer_errors = errors
        errors.append(_diagnostic_error(error))


def _repository_workflow_state(runner: Any) -> dict[str, Any]:
    """Collect read-only repository, Actions, YAML, and workflow registration state."""

    captured: dict[str, Any] = {
        "captured_at": _utc_now(),
        "repository": {"name": getattr(runner, "repo_name", None)},
        "actions_permissions": {},
        "registered_workflows": [],
        "expected_workflows": {},
    }
    expected = {
        path: sorted(events)
        for path, events in (getattr(runner, "_workflow_events", None) or {}).items()
    }
    repository = None
    try:
        repository = runner.gh_client.repository
        actual_id = getattr(repository, "id", None)
        bound_id = getattr(runner.gh_client, "bound_repository_id", None)
        default_branch = getattr(repository, "default_branch", None)
        captured["repository"].update(
            {
                "id": actual_id,
                "bound_id": bound_id,
                "identity_matches": (
                    actual_id == bound_id if bound_id is not None else None
                ),
                "default_branch": default_branch,
            }
        )
    except Exception as error:
        captured["repository"]["error"] = _diagnostic_error(error)

    try:
        response = runner.gh_client.request(
            "GET", f"/repos/{runner.repo_name}/actions/permissions"
        )
        permissions = response.json()
        captured["actions_permissions"] = {
            key: permissions.get(key)
            for key in ("enabled", "allowed_actions", "selected_actions_url")
            if key in permissions
        }
    except Exception as error:
        captured["actions_permissions"] = {"error": _diagnostic_error(error)}

    registered_by_path: dict[str, list[dict[str, Any]]] = {}
    if repository is not None:
        try:
            for workflow in islice(repository.get_workflows(), 100):
                item = {
                    "id": getattr(workflow, "id", None),
                    "name": getattr(workflow, "name", None),
                    "path": getattr(workflow, "path", None),
                    "state": getattr(workflow, "state", None),
                }
                captured["registered_workflows"].append(item)
                path = str(item["path"] or "").split("@", 1)[0]
                registered_by_path.setdefault(path, []).append(item)
        except Exception as error:
            captured["registered_workflows_error"] = _diagnostic_error(error)

    default_branch = captured["repository"].get("default_branch")
    for path, events in expected.items():
        yaml_state: dict[str, Any]
        if repository is None or not default_branch:
            yaml_state = {"exists": None, "error": "repository or default branch unavailable"}
        else:
            try:
                content = repository.get_contents(path, ref=default_branch)
                yaml_state = {
                    "exists": True,
                    "path": getattr(content, "path", path),
                    "sha": getattr(content, "sha", None),
                    "size": getattr(content, "size", None),
                    "type": getattr(content, "type", None),
                }
            except Exception as error:
                yaml_state = {
                    "exists": False if getattr(error, "status", None) == 404 else None,
                    "error": _diagnostic_error(error),
                }
        captured["expected_workflows"][path] = {
            "events": events,
            "default_branch_yaml": yaml_state,
            "registrations": registered_by_path.get(path, []),
        }
    return captured


def _initialize_workflow_diagnostic(runner: Any) -> None:
    runner._workflow_diagnostics = {
        "schema_version": "causentry_gitinject_workflow_diagnostic_v1",
        "created_at": _utc_now(),
        "pre_trigger": _repository_workflow_state(runner),
        "wait_attempts": [],
    }


def _workflow_diagnostic_signals(diagnostic: dict[str, Any]) -> list[dict[str, Any]]:
    state = diagnostic.get("timeout_repository_state") or diagnostic.get("pre_trigger") or {}
    signals: list[dict[str, Any]] = []
    permissions = state.get("actions_permissions", {})
    if state.get("repository", {}).get("identity_matches") is False:
        signals.append({"code": "repository_identity_mismatch"})
    if permissions.get("enabled") is False:
        signals.append({"code": "repository_actions_disabled"})
    for path, expected in state.get("expected_workflows", {}).items():
        yaml_state = expected.get("default_branch_yaml", {})
        if yaml_state.get("exists") is False:
            signals.append({"code": "workflow_yaml_missing_on_default_branch", "path": path})
        registrations = expected.get("registrations", [])
        if not registrations:
            signals.append({"code": "workflow_not_registered", "path": path})
        for workflow in registrations:
            if workflow.get("state") != "active":
                signals.append(
                    {
                        "code": "workflow_disabled",
                        "path": path,
                        "workflow_id": workflow.get("id"),
                        "state": workflow.get("state"),
                    }
                )

    attempts = list(diagnostic.get("wait_attempts", []))
    timeout_snapshot = diagnostic.get("timeout_run_snapshot")
    if isinstance(timeout_snapshot, dict):
        attempts.append(timeout_snapshot)
    runs = [run for attempt in attempts for run in attempt.get("runs", [])]
    if not runs:
        signals.append({"code": "no_workflow_runs_observed"})
    else:
        approval_runs = [
            run for run in runs if run.get("approval_state") is not None
        ]
        if approval_runs:
            signals.append(
                {
                    "code": "workflow_approval_waiting",
                    "run_ids": sorted(
                        {run.get("id") for run in approval_runs if run.get("id") is not None}
                    ),
                    "states": sorted(
                        {run["approval_state"] for run in approval_runs}
                    ),
                }
            )
        eligible = [run for run in runs if run.get("eligible")]
        if not eligible:
            reasons = sorted(
                {run.get("excluded_by") for run in runs if run.get("excluded_by")}
            )
            signals.append(
                {"code": "all_observed_runs_filtered", "filter_reasons": reasons}
            )
        elif not any(run.get("status") == "completed" for run in eligible):
            signals.append(
                {
                    "code": "matching_workflow_run_not_completed",
                    "run_ids": sorted(
                        {run.get("id") for run in eligible if run.get("id") is not None}
                    ),
                }
            )
    if isinstance(timeout_snapshot, dict) and any(
        run.get("eligible") and run.get("status") == "completed"
        for run in timeout_snapshot.get("runs", [])
    ):
        signals.append({"code": "matching_completed_run_observed_at_timeout_cleanup"})
    workflow_query_error = any(
        expected.get("default_branch_yaml", {}).get("error")
        for expected in state.get("expected_workflows", {}).values()
    )
    timeout_query_error = (
        isinstance(timeout_snapshot, dict) and timeout_snapshot.get("error")
    )
    if any(
        isinstance(value, dict) and value.get("error")
        for value in (
            state.get("repository", {}),
            state.get("actions_permissions", {}),
        )
    ) or any(
        (
            state.get("registered_workflows_error"),
            workflow_query_error,
            timeout_query_error,
        )
    ):
        signals.append({"code": "diagnostic_query_error"})
    return signals


def _persist_workflow_diagnostic(
    runner: Any,
    result: dict[str, Any],
    scenario: Any,
) -> Path | None:
    diagnostic = getattr(runner, "_workflow_diagnostics", None)
    if not isinstance(diagnostic, dict) or not result.get("runs_dir"):
        return None
    is_timeout = result.get("error") == WORKFLOW_WAIT_TIMEOUT
    diagnostic["result_error"] = result.get("error")
    diagnostic["captured_before_cleanup_at"] = _utc_now()
    diagnostic["observer_errors"] = list(
        getattr(runner, "_workflow_diagnostic_observer_errors", [])
    )
    if is_timeout:
        diagnostic["timeout_repository_state"] = _repository_workflow_state(runner)
        start_time = getattr(runner, "_trial_state", {}).get("triggered_at")
        expected_event = None
        if scenario is not None:
            expected_event = scenario.get_event().get("event_type")
        if start_time is not None:
            try:
                _, snapshot = _evaluate_workflow_runs(
                    runner, start_time, expected_event
                )
                diagnostic["timeout_run_snapshot"] = snapshot
            except Exception as error:
                diagnostic["timeout_run_snapshot"] = {
                    "captured_at": _utc_now(),
                    "error": _diagnostic_error(error),
                    "runs": [],
                }
    diagnostic["possible_cause_signals"] = _workflow_diagnostic_signals(diagnostic)
    path = Path(result["runs_dir"]) / "workflow_diagnostic.json"
    _write_json_exclusive(path, diagnostic)
    result["workflow_diagnostic"] = str(path)
    return path


def _wait_for_run_with_safe_workflow_runs(
    runner: Any,
    start_time: float,
    expected_event: str | None = None,
) -> tuple[int, Any] | None:
    """GitInject 0.1.0 ``_wait_for_run`` with only empty-run slicing fixed."""

    try:
        candidates, observation = _evaluate_workflow_runs(
            runner, start_time, expected_event
        )
    except Exception as error:
        _record_wait_observation(
            runner,
            {
                "captured_at": _utc_now(),
                "start_time": start_time,
                "expected_event": expected_event,
                "decision": "query_error",
                "error": _diagnostic_error(error),
                "runs": [],
            },
        )
        raise
    _record_wait_observation(runner, observation)
    if len(candidates) > 1:
        raise RuntimeError(
            "Ambiguous workflow attribution: multiple runs match this trigger"
        )
    if not candidates or candidates[0].status != "completed":
        return None
    return candidates[0].id, candidates[0]


def _build_live_types(expected_owner: str, expected_prefix: str):
    from gitinject.runner import BenchmarkRunner
    from gitinject.utils.gh_client import GitHubClient
    from tenacity import retry, retry_if_result, stop_after_attempt, wait_exponential

    class IdentityBindingGitHubClient(GitHubClient):
        bound_repository_id: int | None = None

        def set_variable(self, name: str, value: str):
            if name != REPOSITORY_ID_VARIABLE:
                return super().set_variable(name, value)
            if value != REPOSITORY_ID_SENTINEL:
                return False, "Repository ID variable did not contain the binding sentinel"
            repository = self.repository
            if repository.owner.login.casefold() != expected_owner.casefold():
                return False, "Created repository owner differs from the approved owner"
            if not repository.name.startswith(expected_prefix):
                return False, "Created repository name differs from the approved prefix"
            self.bound_repository_id = int(repository.id)
            return super().set_variable(name, str(self.bound_repository_id))

    class EvidenceCollectingBenchmarkRunner(BenchmarkRunner):
        def _prepare_trial(self, scenario, metadata=None):
            result = _prepare_trial_with_safe_workflow_runs(self, scenario, metadata)
            try:
                _initialize_workflow_diagnostic(self)
            except Exception as error:
                self._workflow_diagnostics = {
                    "schema_version": "causentry_gitinject_workflow_diagnostic_v1",
                    "created_at": _utc_now(),
                    "pre_trigger": {"error": _diagnostic_error(error)},
                    "wait_attempts": [],
                }
            return result

        def _record_workflow_wait_observation(self, observation):
            diagnostic = getattr(self, "_workflow_diagnostics", None)
            if not isinstance(diagnostic, dict):
                diagnostic = {
                    "schema_version": "causentry_gitinject_workflow_diagnostic_v1",
                    "created_at": _utc_now(),
                    "wait_attempts": [],
                }
                self._workflow_diagnostics = diagnostic
            attempts = diagnostic.setdefault("wait_attempts", [])
            observation["attempt"] = len(attempts) + 1
            attempts.append(observation)

        @retry(
            retry=retry_if_result(lambda res: res is None),
            stop=stop_after_attempt(60),
            wait=wait_exponential(multiplier=1, min=2, max=10),
            retry_error_callback=lambda state: None,
        )
        def _wait_for_run(self, start_time, expected_event=None):
            return _wait_for_run_with_safe_workflow_runs(
                self,
                start_time,
                expected_event=expected_event,
            )

        def run(self, *args, **kwargs):
            result, failure = _call_with_swallowed_exception_trace(
                lambda: super(EvidenceCollectingBenchmarkRunner, self).run(
                    *args, **kwargs
                ),
                target_code=BenchmarkRunner.run.__code__,
            )
            if failure is not None:
                try:
                    _record_failure_diagnostic(result, failure)
                except (AttriGuardIntegrationError, OSError, ValueError) as error:
                    result["failure_diagnostic_error"] = (
                        f"{type(error).__name__}: {error}"
                    )
            return result

        def _cleanup(self, scenario, result, context):
            is_timeout = result.get("error") == WORKFLOW_WAIT_TIMEOUT
            try:
                _persist_workflow_diagnostic(self, result, scenario)
            except Exception as error:
                result["workflow_diagnostic_error"] = (
                    f"{type(error).__name__}: {_sanitize_traceback(str(error))}"
                )
                if is_timeout:
                    result["cleanup_deferred"] = True
                    return
            run_id = result.get("run_id")
            repository_id = getattr(self.gh_client, "bound_repository_id", None)
            if run_id and repository_id:
                try:
                    evidence = collect_gitinject_artifact(
                        transport=GitHubArtifactTransport(
                            token=self.gh_client.token,
                            api_url=os.environ.get(
                                "GITHUB_API_URL", "https://api.github.com"
                            ),
                        ),
                        repository=self.repo_name,
                        repository_id=repository_id,
                        expected_owner=expected_owner,
                        expected_prefix=expected_prefix,
                        run_id=int(run_id),
                        destination=Path(result["runs_dir"]) / "attriguard-evidence",
                    )
                    result["attriguard_evidence"] = {
                        "destination": str(evidence.destination),
                        "collection_sha256": evidence.manifest["collection_sha256"],
                        "trial_schema": evidence.trial.get("schema_version"),
                    }
                    if evidence.trial.get("schema_version") == "causentry_attriguard_gitinject_trial_v3":
                        binding = bind_official_and_local_results(
                            local_receipt=evidence.trial,
                            official_result=result,
                            local_validity=evidence.validity,
                        )
                        binding_path = evidence.destination / "binding.json"
                        _write_json_exclusive(binding_path, binding)
                        result["attriguard_evidence"]["binding"] = str(binding_path)
                except Exception as error:
                    result["evidence_collection_error"] = f"{type(error).__name__}: {error}"
                    result["cleanup_deferred"] = True
                    result.setdefault(
                        "error",
                        "Evidence collection failed; repository cleanup was intentionally deferred",
                    )
                    return
            elif run_id:
                result["evidence_collection_error"] = (
                    "Created repository ID was not bound before the workflow run"
                )
                result["cleanup_deferred"] = True
                result.setdefault(
                    "error",
                    "Repository identity binding failed; cleanup was intentionally deferred",
                )
                return
            super()._cleanup(scenario, result, context)

    return IdentityBindingGitHubClient, EvidenceCollectingBenchmarkRunner


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-live", action="store_true")
    parser.add_argument("--workflow", choices=sorted(WORKFLOWS), required=True)
    parser.add_argument("--scenario", default="supply_chain_malicious_code")
    parser.add_argument("--repo-prefix", required=True, help="Approved owner/name-prefix")
    parser.add_argument("--workspace", type=Path, default=ROOT)
    args = parser.parse_args()

    if args.scenario != "supply_chain_malicious_code":
        parser.error("Only the pinned supply_chain_malicious_code scenario is authorized")
    if "/" not in args.repo_prefix:
        parser.error("--repo-prefix must include the approved owner, for example owner/ag-bench")
    expected_owner, expected_prefix = args.repo_prefix.split("/", 1)
    if not expected_owner or not expected_prefix:
        parser.error("--repo-prefix must contain non-empty owner and prefix components")
    manifest = load_official_gitinject_manifest()
    plan = {
        "mode": "live" if args.execute_live else "plan_only",
        "official_gitinject_version": manifest["package"]["version"],
        "workflow": args.workflow,
        "scenario": args.scenario,
        "repo_prefix": args.repo_prefix,
        "repository_identity_binding": REPOSITORY_ID_VARIABLE,
        "cleanup_policy": "only_after_verified_artifact_collection",
        "network_calls": bool(args.execute_live),
        "remote_writes": bool(args.execute_live),
    }
    if not args.execute_live:
        print(json.dumps(plan, indent=2, sort_keys=True))
        return 0

    required_environment = (
        "GITHUB_TOKEN",
        "ATTACKER_GITHUB_TOKEN",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "ATTRIGUARD_BENCHMARK_OWNER",
        "ATTRIGUARD_BENCHMARK_PREFIX",
        "ATTRIGUARD_EVALUATION_REPOSITORY",
        "ATTRIGUARD_EVALUATION_REF",
        "ATTRIGUARD_TARGET_MODEL",
        "ATTRIGUARD_AUXILIARY_MODEL",
    )
    missing = [name for name in required_environment if not os.environ.get(name)]
    if missing:
        parser.error("Live mode requires environment variables: " + ", ".join(missing))
    if os.environ["ATTRIGUARD_BENCHMARK_OWNER"].casefold() != expected_owner.casefold():
        parser.error("ATTRIGUARD_BENCHMARK_OWNER differs from --repo-prefix owner")
    if os.environ["ATTRIGUARD_BENCHMARK_PREFIX"] != expected_prefix:
        parser.error("ATTRIGUARD_BENCHMARK_PREFIX differs from --repo-prefix prefix")

    os.environ[REPOSITORY_ID_VARIABLE] = REPOSITORY_ID_SENTINEL
    try:
        IdentityClient, Runner = _build_live_types(expected_owner, expected_prefix)
        owner_client = IdentityClient()
        runner = Runner(
            str(args.workspace.resolve(strict=True)),
            repo_prefix=args.repo_prefix,
            gh_client=owner_client,
        )
        result = runner.run(
            args.workflow,
            args.scenario,
            cleanup=True,
            log_llm_input=False,
        )
    except (AttriGuardIntegrationError, OSError, RuntimeError, ValueError) as error:
        print(f"Official GitInject trial failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True, default=str))
    return 1 if result.get("error") else 0


if __name__ == "__main__":
    raise SystemExit(main())

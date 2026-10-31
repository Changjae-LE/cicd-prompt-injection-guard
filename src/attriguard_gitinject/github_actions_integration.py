"""Official GitInject/GitHub Actions integration outside the AttriGuard core.

The target checkout is treated strictly as untrusted data.  The only live side
effect supported by this boundary is one ordinary pull-request review comment
inside an explicitly named ephemeral benchmark repository.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Any, Callable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .attriguard_cicd import (
    DEFAULT_SUPPLY_CHAIN_CASE,
    FILE_LOOKUP_CONTRACT,
    GITINJECT_FAITHFUL_SYSTEM_MESSAGE,
    AttriGuardIntegrationError,
    GitInjectCICDWorkspace,
    canonical_sha256,
    file_sha256,
    load_json_document,
)


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_GITINJECT_MANIFEST = (
    ROOT / "dataset" / "gitinject" / "official_gitinject_manifest.json"
)
DEFAULT_GITINJECT_SCENARIO_REGISTRY = (
    ROOT / "dataset" / "gitinject" / "official_scenario_registry.json"
)
_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
SUPPORTED_GITINJECT_SCENARIOS = frozenset(
    {"supply_chain_malicious_code", "vulnerable_code_review"}
)


class ChangedFileSetMismatchError(AttriGuardIntegrationError):
    """Exact official changed-file contract mismatch, with paths-only evidence."""

    def __init__(
        self,
        *,
        expected: Sequence[str],
        observed: Sequence[str],
        scenario_id: str = "supply_chain_malicious_code",
    ):
        expected_set = set(expected)
        observed_set = set(observed)
        self.changed_file_diagnostic = {
            "schema_version": "causentry_gitinject_changed_file_validation_v1",
            "scenario_id": scenario_id,
            "matches_official_scenario": False,
            "expected_paths": sorted(expected_set),
            "observed_paths": sorted(observed_set),
            "missing_paths": sorted(expected_set - observed_set),
            "extra_paths": sorted(observed_set - expected_set),
            "contains_file_contents": False,
        }
        super().__init__(f"Changed-file set does not match official {scenario_id}")


def _validate_scenario_contract(
    scenario_id: str,
    scenario: Mapping[str, Any],
) -> None:
    if scenario.get("id") != scenario_id:
        raise AttriGuardIntegrationError(
            f"Official GitInject scenario ID mismatch: {scenario_id}"
        )
    if scenario.get("type") not in {"benign", "malicious"}:
        raise AttriGuardIntegrationError(
            f"Official GitInject scenario type is invalid: {scenario_id}"
        )
    if scenario.get("condition") not in {"attack", "benign"}:
        raise AttriGuardIntegrationError(
            f"Official GitInject scenario condition is invalid: {scenario_id}"
        )
    expected_condition = "attack" if scenario.get("type") == "malicious" else "benign"
    if scenario.get("condition") != expected_condition:
        raise AttriGuardIntegrationError(
            f"Official GitInject scenario type/condition mismatch: {scenario_id}"
        )
    if scenario.get("category") != "code-review" or scenario.get("event") != "pull_request":
        raise AttriGuardIntegrationError(
            f"Official GitInject scenario workflow contract is invalid: {scenario_id}"
        )
    if not re.fullmatch(r"[0-9a-f]{64}", str(scenario.get("scenario_sha256", ""))):
        raise AttriGuardIntegrationError(
            f"Official GitInject scenario hash is invalid: {scenario_id}"
        )
    changed_files = scenario.get("changed_files")
    if not isinstance(changed_files, Mapping) or not changed_files:
        raise AttriGuardIntegrationError(
            f"Official GitInject changed-file pin is missing: {scenario_id}"
        )
    normalized_paths: set[str] = set()
    for path, digest in changed_files.items():
        normalized = GitInjectCICDWorkspace._normalize_repo_path(str(path))
        if normalized != path or normalized in normalized_paths:
            raise AttriGuardIntegrationError(
                f"Official GitInject changed-file path is invalid: {path}"
            )
        normalized_paths.add(normalized)
        if not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
            raise AttriGuardIntegrationError(
                f"Official GitInject changed-file hash is invalid: {path}"
            )
    for evaluator_name in ("utility_evaluator", "security_evaluator"):
        evaluator = scenario.get(evaluator_name)
        if not isinstance(evaluator, Mapping) or not str(
            evaluator.get("implementation", "")
        ).startswith("gitinject.evaluators."):
            raise AttriGuardIntegrationError(
                f"Official GitInject {evaluator_name} pin is invalid: {scenario_id}"
            )
        if not re.fullmatch(r"[0-9a-f]{64}", str(evaluator.get("source_sha256", ""))):
            raise AttriGuardIntegrationError(
                f"Official GitInject {evaluator_name} hash is invalid: {scenario_id}"
            )
    if scenario.get("type") == "benign":
        pull_request = scenario.get("pull_request")
        if (
            not isinstance(pull_request, Mapping)
            or not isinstance(pull_request.get("title"), str)
            or not isinstance(pull_request.get("body"), str)
            or not isinstance(scenario.get("user_task"), str)
            or scenario.get("payload_sha256") is not None
        ):
            raise AttriGuardIntegrationError(
                f"Official benign GitInject input contract is invalid: {scenario_id}"
            )


def get_official_scenario_contract(
    manifest: Mapping[str, Any],
    scenario_id: str,
) -> dict[str, Any]:
    scenarios = manifest.get("supported_scenarios")
    if not isinstance(scenarios, Mapping) or scenario_id not in scenarios:
        raise AttriGuardIntegrationError(
            f"Unsupported official GitInject scenario: {scenario_id}"
        )
    scenario = scenarios[scenario_id]
    if not isinstance(scenario, Mapping):
        raise AttriGuardIntegrationError(
            f"Official GitInject scenario contract is invalid: {scenario_id}"
        )
    _validate_scenario_contract(scenario_id, scenario)
    return copy.deepcopy(dict(scenario))


def load_official_gitinject_manifest(
    path: str | Path = DEFAULT_GITINJECT_MANIFEST,
    *,
    registry_path: str | Path | None = None,
) -> dict[str, Any]:
    manifest_path = Path(path)
    manifest = load_json_document(manifest_path)
    if manifest.get("schema_version") != "causentry_official_gitinject_manifest_v1":
        raise AttriGuardIntegrationError("Unsupported official GitInject manifest")
    package = manifest.get("package")
    if not isinstance(package, Mapping) or package.get("version") != "0.1.0":
        raise AttriGuardIntegrationError("Official GitInject version pin is missing")
    wheel = package.get("wheel")
    if not isinstance(wheel, Mapping) or not re.fullmatch(
        r"[0-9a-f]{64}", str(wheel.get("sha256", ""))
    ):
        raise AttriGuardIntegrationError("Official GitInject wheel hash is invalid")
    scenario = manifest.get("scenario")
    if not isinstance(scenario, Mapping):
        raise AttriGuardIntegrationError("Official GitInject scenario pin is missing")
    if scenario.get("id") != "supply_chain_malicious_code":
        raise AttriGuardIntegrationError("Unexpected official GitInject scenario")
    changed_files = scenario.get("changed_files")
    if not isinstance(changed_files, Mapping) or set(changed_files) != {
        "CLAUDE.md",
        "src/flask/csrf.py",
        "tests/test_csrf.py",
    }:
        raise AttriGuardIntegrationError("Official GitInject changed-file pin is invalid")
    for path, digest in changed_files.items():
        if not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
            raise AttriGuardIntegrationError(
                f"Official GitInject changed-file hash is invalid: {path}"
            )
    resolved_registry_path = (
        Path(registry_path)
        if registry_path is not None
        else manifest_path.with_name(DEFAULT_GITINJECT_SCENARIO_REGISTRY.name)
    )
    registry = load_json_document(resolved_registry_path)
    if (
        registry.get("schema_version")
        != "causentry_official_gitinject_scenario_registry_v1"
        or registry.get("gitinject_version") != package.get("version")
    ):
        raise AttriGuardIntegrationError(
            "Official GitInject scenario registry is incompatible"
        )
    supported = registry.get("scenarios")
    if not isinstance(supported, Mapping) or set(supported) != set(
        SUPPORTED_GITINJECT_SCENARIOS
    ):
        raise AttriGuardIntegrationError(
            "Official GitInject supported-scenario pins are incomplete"
        )
    manifest["supported_scenarios"] = copy.deepcopy(dict(supported))
    for scenario_id in sorted(SUPPORTED_GITINJECT_SCENARIOS):
        contract = get_official_scenario_contract(manifest, scenario_id)
        if scenario_id == "supply_chain_malicious_code" and (
            contract.get("scenario_sha256") != scenario.get("scenario_sha256")
            or contract.get("payload_sha256") != scenario.get("payload_sha256")
            or contract.get("changed_files") != scenario.get("changed_files")
        ):
            raise AttriGuardIntegrationError(
                "Legacy supply-chain pin differs from its supported-scenario contract"
            )
    manifest["supported_scenarios_sha256"] = file_sha256(resolved_registry_path)
    return manifest


def validate_benchmark_repository(
    repository: str,
    *,
    expected_owner: str,
    expected_prefix: str,
    repository_id: int | None = None,
    expected_repository_id: int | None = None,
) -> tuple[str, str]:
    parts = repository.split("/")
    if len(parts) != 2 or not all(_NAME.fullmatch(part or "") for part in parts):
        raise AttriGuardIntegrationError("GitHub repository must be owner/name")
    if not _NAME.fullmatch(expected_owner or ""):
        raise AttriGuardIntegrationError("Invalid expected benchmark owner")
    if not _NAME.fullmatch(expected_prefix or ""):
        raise AttriGuardIntegrationError("Invalid benchmark repository prefix")
    owner, name = parts
    if owner.casefold() != expected_owner.casefold() or not name.startswith(expected_prefix):
        raise AttriGuardIntegrationError(
            "Live side effects are restricted to the configured benchmark owner/prefix"
        )
    if repository_id is not None or expected_repository_id is not None:
        if (
            not isinstance(repository_id, int)
            or isinstance(repository_id, bool)
            or repository_id < 1
            or not isinstance(expected_repository_id, int)
            or isinstance(expected_repository_id, bool)
            or expected_repository_id < 1
        ):
            raise AttriGuardIntegrationError("Benchmark repository IDs must be positive integers")
        if repository_id != expected_repository_id:
            raise AttriGuardIntegrationError(
                "Live side effects are restricted to the provisioner-bound repository ID"
            )
    return owner, name


Transport = Callable[
    [str, str, Mapping[str, str], Mapping[str, Any] | None], Any
]


def _github_transport(
    method: str,
    url: str,
    headers: Mapping[str, str],
    payload: Mapping[str, Any] | None,
) -> Any:
    request = Request(
        url,
        data=(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
            if payload is not None
            else None
        ),
        headers=dict(headers),
        method=method,
    )
    try:
        with urlopen(request, timeout=30) as response:
            value = json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        raise AttriGuardIntegrationError(
            f"GitHub review API returned HTTP {error.code}"
        ) from error
    except (URLError, TimeoutError, UnicodeError, json.JSONDecodeError) as error:
        raise AttriGuardIntegrationError("GitHub review API request failed") from error
    return value


@dataclass
class GitHubReviewCommentSink:
    token: str
    repository: str
    pull_request_number: int
    repository_id: int
    expected_repository_id: int
    idempotency_key: str
    expected_owner: str
    expected_prefix: str
    api_url: str = "https://api.github.com"
    transport: Transport = _github_transport
    _completed_action_id: str | None = field(default=None, init=False, repr=False)
    _completed_result: Mapping[str, Any] | None = field(
        default=None, init=False, repr=False
    )

    def __post_init__(self) -> None:
        validate_benchmark_repository(
            self.repository,
            expected_owner=self.expected_owner,
            expected_prefix=self.expected_prefix,
            repository_id=self.repository_id,
            expected_repository_id=self.expected_repository_id,
        )
        if not isinstance(self.pull_request_number, int) or self.pull_request_number < 1:
            raise AttriGuardIntegrationError("Pull-request number must be positive")
        if not self.token:
            raise AttriGuardIntegrationError("GITHUB_TOKEN is required for live review output")
        if not self.api_url.startswith("https://"):
            raise AttriGuardIntegrationError("GitHub API URL must use HTTPS")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", self.idempotency_key or ""):
            raise AttriGuardIntegrationError("Invalid post_review idempotency key")

    def __call__(
        self,
        tool: str,
        arguments: Mapping[str, Any],
        action_id: str,
    ) -> Mapping[str, Any]:
        if tool != "post_review":
            raise AttriGuardIntegrationError(
                f"Live CI/CD action is not authorized: {tool}"
            )
        body = arguments.get("body")
        if not isinstance(body, str) or not body.strip():
            raise AttriGuardIntegrationError("post_review requires a non-empty body")
        if not re.fullmatch(r"[0-9a-f]{64}", action_id):
            raise AttriGuardIntegrationError("post_review action_id must be SHA-256")
        if self._completed_action_id is not None:
            if action_id != self._completed_action_id:
                raise AttriGuardIntegrationError(
                    "Only one distinct post_review action is authorized per trial"
                )
            return dict(self._completed_result or {})
        url = (
            f"{self.api_url.rstrip('/')}/repos/{self.repository}/pulls/"
            f"{self.pull_request_number}/reviews"
        )
        marker = f"<!-- attriguard-gitinject-run:{self.idempotency_key} -->"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "attriguard-gitinject-evaluation/0.1.0",
        }
        existing = self.transport("GET", f"{url}?per_page=100", headers, None)
        if not isinstance(existing, Sequence) or isinstance(existing, (str, bytes)):
            raise AttriGuardIntegrationError("GitHub reviews API returned a non-list")
        for review in existing:
            if not isinstance(review, Mapping) or marker not in str(review.get("body", "")):
                continue
            user = review.get("user")
            author = user.get("login") if isinstance(user, Mapping) else None
            if str(author).casefold() != "github-actions[bot]":
                continue
            result = self._result_from_review(
                review,
                action_id=action_id,
                status="already_posted",
                idempotent_replay=True,
            )
            self._completed_action_id = action_id
            self._completed_result = result
            return dict(result)
        response = self.transport(
            "POST",
            url,
            headers,
            {"body": f"{body.rstrip()}\n\n{marker}", "event": "COMMENT"},
        )
        if not isinstance(response, Mapping):
            raise AttriGuardIntegrationError("GitHub review API returned a non-object")
        result = self._result_from_review(
            response,
            action_id=action_id,
            status="posted",
            idempotent_replay=False,
        )
        self._completed_action_id = action_id
        self._completed_result = result
        return dict(result)

    @staticmethod
    def _result_from_review(
        response: Mapping[str, Any],
        *,
        action_id: str,
        status: str,
        idempotent_replay: bool,
    ) -> Mapping[str, Any]:
        user = response.get("user")
        author = user.get("login") if isinstance(user, Mapping) else None
        return {
            "status": status,
            "review_id": response.get("id"),
            "html_url": response.get("html_url"),
            "author": author,
            "state": response.get("state"),
            "submitted_at": response.get("submitted_at"),
            "action_id_echo": action_id,
            "idempotent_replay": idempotent_replay,
        }


def load_pull_request_event(path: str | Path) -> dict[str, Any]:
    event = load_json_document(path)
    pull_request = event.get("pull_request")
    repository = event.get("repository")
    if not isinstance(pull_request, Mapping) or not isinstance(repository, Mapping):
        raise AttriGuardIntegrationError("Expected a GitHub pull-request event payload")
    if not isinstance(event.get("number"), int):
        raise AttriGuardIntegrationError("GitHub event lacks a pull-request number")
    if not isinstance(repository.get("full_name"), str):
        raise AttriGuardIntegrationError("GitHub event lacks repository.full_name")
    repository_id = repository.get("id")
    if (
        not isinstance(repository_id, int)
        or isinstance(repository_id, bool)
        or repository_id < 1
    ):
        raise AttriGuardIntegrationError("GitHub event lacks a positive repository.id")
    return event


def git_changed_paths(
    repository_root: str | Path,
    *,
    base_sha: str,
    head_sha: str,
) -> list[str]:
    root = Path(repository_root).resolve(strict=True)
    for label, value in (("base", base_sha), ("head", head_sha)):
        if not re.fullmatch(r"[0-9a-fA-F]{40}", value or ""):
            raise AttriGuardIntegrationError(f"Pull-request {label} SHA must be 40-hex")
    command = [
        "git",
        "-C",
        str(root),
        "diff",
        "--name-only",
        "-z",
        "--diff-filter=ACMRT",
        base_sha,
        head_sha,
        "--",
    ]
    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError, UnicodeError) as error:
        raise AttriGuardIntegrationError(
            "Unable to derive changed paths from the checked-out pull request"
        ) from error
    try:
        paths = sorted(
            {
                raw_path.decode("utf-8")
                for raw_path in completed.stdout.split(b"\0")
                if raw_path
            }
        )
    except UnicodeError as error:
        raise AttriGuardIntegrationError(
            "Unable to decode changed paths from the checked-out pull request"
        ) from error
    if not paths:
        raise AttriGuardIntegrationError("Pull-request diff contains no readable changed files")
    return paths


def _event_sha(pull_request: Mapping[str, Any], side: str) -> str:
    value = pull_request.get(side)
    sha = value.get("sha") if isinstance(value, Mapping) else None
    if not isinstance(sha, str):
        raise AttriGuardIntegrationError(f"GitHub event lacks pull_request.{side}.sha")
    return sha


def build_live_gitinject_workspace(
    *,
    event: Mapping[str, Any],
    repository_root: str | Path,
    action_sink: GitHubReviewCommentSink,
    changed_paths: Sequence[str] | None = None,
    case_root: str | Path = DEFAULT_SUPPLY_CHAIN_CASE,
    scenario_id: str = "supply_chain_malicious_code",
) -> tuple[GitInjectCICDWorkspace, str, str, dict[str, Any]]:
    """Bind the official scenario checkout to the existing AgentDojo adapter."""

    manifest = load_official_gitinject_manifest()
    scenario_contract = get_official_scenario_contract(manifest, scenario_id)
    root = Path(repository_root).resolve(strict=True)
    pull_request_event = event.get("pull_request")
    repository = event.get("repository")
    if not isinstance(pull_request_event, Mapping) or not isinstance(repository, Mapping):
        raise AttriGuardIntegrationError("Expected a GitHub pull-request event payload")
    if repository.get("full_name") != action_sink.repository:
        raise AttriGuardIntegrationError("Event repository and review sink repository differ")
    if repository.get("id") != action_sink.expected_repository_id:
        raise AttriGuardIntegrationError(
            "Event repository ID and provisioner-bound repository ID differ"
        )

    fixture_root: Path | None = None
    fixture: Mapping[str, Any] | None = None
    if scenario_id == "supply_chain_malicious_code":
        fixture_root = Path(case_root).resolve(strict=True)
        fixture = load_json_document(fixture_root / "fixture_manifest.json")
        metadata = fixture.get("merge_request_metadata")
        expected_title = metadata.get("title") if isinstance(metadata, Mapping) else None
        expected_body = (
            metadata.get("description") if isinstance(metadata, Mapping) else None
        )
    else:
        metadata = scenario_contract.get("pull_request")
        expected_title = metadata.get("title") if isinstance(metadata, Mapping) else None
        expected_body = metadata.get("body") if isinstance(metadata, Mapping) else None
    if not isinstance(metadata, Mapping) or not isinstance(expected_title, str) or not isinstance(expected_body, str):
        raise AttriGuardIntegrationError("Pinned GitInject scenario metadata is missing")
    title = pull_request_event.get("title")
    body = pull_request_event.get("body")
    if title != expected_title or body != expected_body:
        raise AttriGuardIntegrationError(
            f"GitHub event does not match the pinned {scenario_id} scenario"
        )

    if changed_paths is None:
        changed_paths = git_changed_paths(
            root,
            base_sha=_event_sha(pull_request_event, "base"),
            head_sha=_event_sha(pull_request_event, "head"),
        )
    expected_changed_files = scenario_contract["changed_files"]
    observed_changed_paths = sorted(set(changed_paths))
    if set(observed_changed_paths) != set(expected_changed_files):
        raise ChangedFileSetMismatchError(
            expected=tuple(expected_changed_files),
            observed=observed_changed_paths,
            scenario_id=scenario_id,
        )
    normalized = sorted(
        {
            GitInjectCICDWorkspace._normalize_repo_path(path)
            for path in observed_changed_paths
        }
    )

    visible_files: dict[str, str] = {}
    for relative in normalized:
        candidate = root.joinpath(*PurePosixPath(relative).parts).resolve(strict=True)
        try:
            candidate.relative_to(root)
        except ValueError as error:
            raise AttriGuardIntegrationError("Changed path escapes target checkout") from error
        if not candidate.is_file():
            raise AttriGuardIntegrationError(f"Changed path is not a file: {relative}")
        visible_files[relative] = file_sha256(candidate)

    mismatches = {
        relative: {
            "expected": expected_changed_files[relative],
            "actual": visible_files.get(relative),
        }
        for relative in sorted(expected_changed_files)
        if visible_files.get(relative) != expected_changed_files[relative]
    }
    if mismatches:
        raise AttriGuardIntegrationError(
            "Official GitInject changed-file SHA-256 mismatch: "
            + ", ".join(sorted(mismatches))
        )

    if scenario_id == "supply_chain_malicious_code":
        expected_payload_hash = scenario_contract["payload_sha256"]
        if visible_files.get("CLAUDE.md") != expected_payload_hash:
            raise AttriGuardIntegrationError(
                "Official GitInject attack payload SHA-256 mismatch"
            )
        assert fixture_root is not None
        source_manifest = load_json_document(fixture_root / "source_manifest.json")
        artifacts = source_manifest.get("artifacts")
        scenario_artifact = next(
            (
                item
                for item in artifacts
                if isinstance(item, Mapping)
                and item.get("role") == "scenario_definition"
            ),
            None,
        ) if isinstance(artifacts, list) else None
        if not isinstance(scenario_artifact, Mapping) or scenario_artifact.get(
            "preserved_sha256"
        ) != scenario_contract["scenario_sha256"]:
            raise AttriGuardIntegrationError(
                "Pinned GitInject scenario source SHA-256 mismatch"
            )

    model_visible_pull_request = {
        "title": title,
        "description": body,
        "changed_paths": normalized,
    }
    user_task = (
        fixture.get("benign_user_request")
        if fixture is not None
        else scenario_contract.get("user_task")
    )
    if not isinstance(user_task, str) or not user_task:
        raise AttriGuardIntegrationError("Pinned benign review objective is missing")
    input_contract: dict[str, Any] = {
        "benchmark_id": "gitinject",
        "source_case_id": scenario_id,
        "official_gitinject_version": manifest["package"]["version"],
        "official_gitinject_manifest_sha256": file_sha256(DEFAULT_GITINJECT_MANIFEST),
        "condition": scenario_contract["condition"],
        "environment_mode": "gitinject_faithful",
        "configuration_excluded_from_model_input": True,
        "condition_label_excluded_from_model_input": True,
        "model_visible_pull_request": model_visible_pull_request,
        "model_visible_pull_request_sha256": canonical_sha256(model_visible_pull_request),
        "user_task_sha256": sha256(user_task.encode("utf-8")).hexdigest(),
        "system_message_sha256": sha256(
            GITINJECT_FAITHFUL_SYSTEM_MESSAGE.encode("utf-8")
        ).hexdigest(),
        "file_lookup_contract": copy.deepcopy(FILE_LOOKUP_CONTRACT),
        "visible_files": visible_files,
    }
    if scenario_id == "supply_chain_malicious_code":
        assert fixture_root is not None
        input_contract["fixture_manifest_sha256"] = file_sha256(
            fixture_root / "fixture_manifest.json"
        )
    else:
        input_contract["official_scenario_registry_sha256"] = manifest[
            "supported_scenarios_sha256"
        ]
        input_contract["official_scenario_sha256"] = scenario_contract[
            "scenario_sha256"
        ]
        input_contract["official_utility_evaluator"] = copy.deepcopy(
            scenario_contract["utility_evaluator"]
        )
    input_contract["comparison_fingerprint"] = canonical_sha256(input_contract)
    workspace = GitInjectCICDWorkspace(
        repository_root=root,
        pull_request=model_visible_pull_request,
        visible_repo_paths=frozenset(normalized),
        action_sink=action_sink,
    )
    return workspace, user_task, GITINJECT_FAITHFUL_SYSTEM_MESSAGE, input_contract


def bind_official_and_local_results(
    *,
    local_receipt: Mapping[str, Any],
    official_result: Mapping[str, Any],
    local_validity: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a new comparison record without rewriting either source receipt."""

    if local_receipt.get("schema_version") != "causentry_attriguard_gitinject_trial_v3":
        raise AttriGuardIntegrationError("Unsupported local trial receipt")
    analysis = official_result.get("analysis")
    official_evaluator_executed = isinstance(analysis, Mapping) and any(
        key in analysis
        for key in ("security_breached", "utility_achieved", "autonomy_achieved")
    )
    local_validity_item: Mapping[str, Any] | None = None
    if isinstance(local_validity, Mapping):
        if local_validity.get("schema_version") == "causentry_attriguard_gitinject_trial_validity_v1":
            local_validity_item = local_validity
        reports = local_validity.get("reports")
        if local_validity_item is None and isinstance(reports, list) and len(reports) == 1:
            report = reports[0]
            candidate = report.get("validity") if isinstance(report, Mapping) else None
            if isinstance(candidate, Mapping):
                local_validity_item = candidate
    review_state = None
    task_completed = None
    if isinstance(local_validity_item, Mapping):
        review = local_validity_item.get("review_action")
        execution = local_validity_item.get("execution_contract")
        review_state = review.get("state") if isinstance(review, Mapping) else None
        task_completed = (
            execution.get("task_completed") if isinstance(execution, Mapping) else None
        )
    result = {
        "schema_version": "causentry_gitinject_result_binding_v1",
        "source_case_id": local_receipt.get("source_case_id"),
        "configuration": local_receipt.get("configuration"),
        "local_trial_receipt_sha256": canonical_sha256(local_receipt),
        "local_validity_gate": copy.deepcopy(local_validity),
        "official_gitinject_evaluator_executed": official_evaluator_executed,
        "official_gitinject_result": copy.deepcopy(dict(official_result)),
        "outcome_separation": {
            "official_utility_achieved": (
                analysis.get("utility_achieved")
                if isinstance(analysis, Mapping)
                and isinstance(analysis.get("utility_achieved"), bool)
                else None
            ),
            "local_task_completed": task_completed,
            "local_review_action_state": review_state,
            "normal_action_blocked_by_defense": (
                review_state == "review_action_blocked_by_defense"
                if isinstance(review_state, str)
                else None
            ),
        },
        "separation_policy": (
            "Official GitInject verdicts are preserved verbatim; Trial Validity Gate "
            "metrics are not substituted for official ASR."
        ),
    }
    result["binding_sha256"] = canonical_sha256(result)
    return result

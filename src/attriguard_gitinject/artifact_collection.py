"""Safely collect AttriGuard evidence before an ephemeral GitInject repo is removed."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import stat
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen
from zipfile import BadZipFile, ZipFile
import io

from .attriguard_cicd import AttriGuardIntegrationError, canonical_sha256
from .github_actions_integration import validate_benchmark_repository


MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AttriGuardIntegrationError(f"Duplicate JSON key in artifact: {key}")
        result[key] = value
    return result


def _json_bytes(value: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(
            value.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise AttriGuardIntegrationError(f"Invalid {label} JSON in artifact") from error
    if not isinstance(document, dict):
        raise AttriGuardIntegrationError(f"{label} must be a JSON object")
    return document


class GitHubArtifactTransport:
    def __init__(
        self,
        *,
        token: str,
        api_url: str = "https://api.github.com",
    ) -> None:
        if not token:
            raise AttriGuardIntegrationError("GITHUB_TOKEN is required to collect artifacts")
        if not api_url.startswith("https://"):
            raise AttriGuardIntegrationError("GitHub API URL must use HTTPS")
        self.token = token
        self.api_url = api_url.rstrip("/")

    def _get(self, endpoint: str, *, signed_redirect: bool = False) -> bytes:
        if not endpoint.startswith("/"):
            raise AttriGuardIntegrationError("GitHub artifact endpoint must be relative")
        request = Request(
            self.api_url + endpoint,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "attriguard-gitinject-evaluation/0.1.0",
            },
            method="GET",
        )
        try:
            if signed_redirect:
                class NoRedirect(HTTPRedirectHandler):
                    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
                        return None

                try:
                    response = build_opener(NoRedirect).open(request, timeout=60)
                except HTTPError as redirect:
                    if redirect.code not in {301, 302, 303, 307, 308}:
                        raise
                    location = redirect.headers.get("Location", "")
                    parsed = urlsplit(location)
                    if (
                        parsed.scheme != "https"
                        or not parsed.netloc
                        or parsed.username
                        or parsed.password
                    ):
                        raise AttriGuardIntegrationError(
                            "GitHub artifact redirect is not a safe HTTPS URL"
                        )
                    response = urlopen(
                        Request(
                            location,
                            headers={
                                "User-Agent": "attriguard-gitinject-evaluation/0.1.0"
                            },
                            method="GET",
                        ),
                        timeout=60,
                    )
                with response:
                    value = response.read(MAX_ARCHIVE_BYTES + 1)
            else:
                with urlopen(request, timeout=60) as response:
                    value = response.read(MAX_ARCHIVE_BYTES + 1)
        except HTTPError as error:
            raise AttriGuardIntegrationError(
                f"GitHub artifact API returned HTTP {error.code}"
            ) from error
        except (URLError, TimeoutError) as error:
            raise AttriGuardIntegrationError("GitHub artifact API request failed") from error
        if len(value) > MAX_ARCHIVE_BYTES:
            raise AttriGuardIntegrationError("GitHub artifact response exceeds size limit")
        return value

    def get_json(self, endpoint: str) -> Mapping[str, Any]:
        return _json_bytes(self._get(endpoint), "GitHub API response")

    def get_bytes(self, endpoint: str) -> bytes:
        return self._get(endpoint, signed_redirect=True)


@dataclass(frozen=True)
class CollectedEvidence:
    destination: Path
    trial: Mapping[str, Any]
    validity: Mapping[str, Any] | None
    manifest: Mapping[str, Any]


def _artifact_documents(archive: bytes) -> tuple[bytes, bytes | None, list[str]]:
    if not archive or len(archive) > MAX_ARCHIVE_BYTES:
        raise AttriGuardIntegrationError("Invalid GitHub Actions artifact size")
    try:
        bundle = ZipFile(io.BytesIO(archive))
    except BadZipFile as error:
        raise AttriGuardIntegrationError("GitHub Actions artifact is not a ZIP file") from error
    with bundle:
        names: list[str] = []
        selected: dict[str, bytes] = {}
        total = 0
        for info in bundle.infolist():
            if "\\" in info.filename:
                raise AttriGuardIntegrationError("Artifact ZIP contains a backslash path")
            relative = PurePosixPath(info.filename)
            if relative.is_absolute() or ".." in relative.parts:
                raise AttriGuardIntegrationError("Artifact ZIP contains an unsafe path")
            mode = info.external_attr >> 16
            if stat.S_IFMT(mode) == stat.S_IFLNK:
                raise AttriGuardIntegrationError("Artifact ZIP symlinks are not allowed")
            if info.is_dir():
                continue
            total += info.file_size
            if total > MAX_UNCOMPRESSED_BYTES:
                raise AttriGuardIntegrationError("Artifact ZIP exceeds uncompressed size limit")
            names.append(relative.as_posix())
            if relative.name not in {"trial.json", "validity.json"}:
                continue
            if relative.name in selected:
                raise AttriGuardIntegrationError(
                    f"Artifact ZIP contains duplicate {relative.name}"
                )
            selected[relative.name] = bundle.read(info)
    if "trial.json" not in selected:
        raise AttriGuardIntegrationError("Artifact ZIP lacks trial.json")
    return selected["trial.json"], selected.get("validity.json"), sorted(names)


def collect_gitinject_artifact(
    *,
    transport: Any,
    repository: str,
    repository_id: int,
    expected_owner: str,
    expected_prefix: str,
    run_id: int,
    destination: str | Path,
) -> CollectedEvidence:
    """Download, verify, and persist exactly one run artifact without overwrites."""

    validate_benchmark_repository(
        repository,
        expected_owner=expected_owner,
        expected_prefix=expected_prefix,
        repository_id=repository_id,
        expected_repository_id=repository_id,
    )
    if not isinstance(run_id, int) or isinstance(run_id, bool) or run_id < 1:
        raise AttriGuardIntegrationError("GitHub Actions run ID must be positive")
    repo_document = transport.get_json(f"/repos/{repository}")
    if repo_document.get("id") != repository_id or repo_document.get("full_name") != repository:
        raise AttriGuardIntegrationError(
            "Remote repository identity differs from the provisioner-bound identity"
        )
    run_document = transport.get_json(
        f"/repos/{repository}/actions/runs/{run_id}"
    )
    run_attempt = run_document.get("run_attempt")
    run_repository = run_document.get("repository")
    if (
        run_document.get("id") != run_id
        or not isinstance(run_attempt, int)
        or isinstance(run_attempt, bool)
        or run_attempt < 1
        or not isinstance(run_repository, Mapping)
        or run_repository.get("id") != repository_id
    ):
        raise AttriGuardIntegrationError(
            "Workflow run identity differs from the provisioner-bound repository"
        )
    listing = transport.get_json(
        f"/repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100"
    )
    artifacts = listing.get("artifacts")
    if not isinstance(artifacts, list):
        raise AttriGuardIntegrationError("GitHub artifact listing is malformed")
    expected_name = f"attriguard-gitinject-{run_id}-{run_attempt}"
    candidates = [
        item
        for item in artifacts
        if isinstance(item, Mapping)
        and item.get("name") == expected_name
        and item.get("expired") is not True
    ]
    if len(candidates) != 1:
        raise AttriGuardIntegrationError(
            f"Expected exactly one AttriGuard artifact for run {run_id}; found {len(candidates)}"
        )
    artifact = candidates[0]
    artifact_id = artifact.get("id")
    if not isinstance(artifact_id, int) or isinstance(artifact_id, bool) or artifact_id < 1:
        raise AttriGuardIntegrationError("GitHub artifact ID is invalid")
    archive = transport.get_bytes(
        f"/repos/{repository}/actions/artifacts/{artifact_id}/zip"
    )
    trial_bytes, validity_bytes, members = _artifact_documents(archive)
    trial = _json_bytes(trial_bytes, "trial receipt")
    validity = (
        _json_bytes(validity_bytes, "validity report")
        if validity_bytes is not None
        else None
    )
    if trial.get("schema_version") == "causentry_attriguard_gitinject_trial_v3":
        if validity is None:
            raise AttriGuardIntegrationError("Successful trial artifact lacks validity.json")
        if validity.get("schema_version") != "causentry_attriguard_gitinject_validity_batch_v1":
            raise AttriGuardIntegrationError("Unexpected validity report schema")
    elif trial.get("schema_version") != "causentry_gitinject_action_error_v1":
        raise AttriGuardIntegrationError("Unexpected trial receipt schema")

    output = Path(destination).resolve()
    if output.exists():
        raise AttriGuardIntegrationError(f"Evidence destination already exists: {output}")
    output.mkdir(parents=True)
    archive_hash = sha256(archive).hexdigest()
    collection_manifest: dict[str, Any] = {
        "schema_version": "causentry_gitinject_artifact_collection_v1",
        "repository": repository,
        "repository_id": repository_id,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "artifact_id": artifact_id,
        "artifact_name": artifact.get("name"),
        "artifact_archive_sha256": archive_hash,
        "members": members,
        "trial_sha256": sha256(trial_bytes).hexdigest(),
        "validity_sha256": (
            sha256(validity_bytes).hexdigest() if validity_bytes is not None else None
        ),
    }
    collection_manifest["collection_sha256"] = canonical_sha256(collection_manifest)
    for name, value in (
        ("artifact.zip", archive),
        ("trial.json", trial_bytes),
        ("validity.json", validity_bytes),
    ):
        if value is None:
            continue
        with (output / name).open("xb") as stream:
            stream.write(value)
    with (output / "collection.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(collection_manifest, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")
    return CollectedEvidence(
        destination=output,
        trial=trial,
        validity=validity,
        manifest=collection_manifest,
    )

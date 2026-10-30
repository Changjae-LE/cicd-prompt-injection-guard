"""Run one identity-bound official GitInject trial with evidence-before-cleanup.

Plan mode is the default.  Live mode imports GitInject 0.1.0, binds the newly
created repository ID into the workflow through the official provisioner's
``set_variable`` call, collects the Actions artifact, and only then permits the
official cleanup sequence to continue.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys


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


def _write_json_exclusive(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
        stream.write("\n")


def _build_live_types(expected_owner: str, expected_prefix: str):
    from gitinject.runner import BenchmarkRunner
    from gitinject.utils.gh_client import GitHubClient

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
        def _cleanup(self, scenario, result, context):
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

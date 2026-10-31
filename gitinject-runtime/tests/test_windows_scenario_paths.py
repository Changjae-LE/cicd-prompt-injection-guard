"""Network-free Windows path regressions for official scenario provisioning."""

from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from gitinject.scenarios.malicious.supply_chain_malicious_code.scenario import (  # noqa: E402
    SupplyChainMaliciousCode,
)
from gitinject.utils import scenario_resources  # noqa: E402
from gitinject.utils.gh_client import GitHubClient  # noqa: E402
from gitinject.utils.scenario_resources import setup_attacker_fork  # noqa: E402
from run_official_gitinject_trial import (  # noqa: E402
    _build_live_types,
    _call_with_scenario_github_client_type,
    _normalize_batch_paths,
)


EXPECTED_POSIX_PATHS = {
    "CLAUDE.md",
    "src/flask/csrf.py",
    "tests/test_csrf.py",
}


class FakeGitRepository:
    """Capture the paths supplied to PyGitHub's create_git_tree boundary."""

    def __init__(self):
        self.created_elements = []
        self.ref = SimpleNamespace(
            object=SimpleNamespace(sha="old-commit"),
            edit=lambda _sha: None,
        )

    def get_git_ref(self, _name):
        return self.ref

    def get_git_commit(self, _sha):
        return SimpleNamespace(tree=SimpleNamespace(sha="base-tree"))

    def get_git_tree(self, sha, recursive=False):
        return SimpleNamespace(sha=sha, tree=[])

    def create_git_tree(self, elements, base_tree=None):
        if base_tree is not None:
            self.created_elements = [
                {
                    "path": vars(element)["_InputGitTreeElement__path"],
                    "content": vars(element)["_InputGitTreeElement__content"],
                }
                for element in elements
            ]
        return SimpleNamespace(sha="new-tree")

    def create_git_commit(self, _message, _tree, _parents):
        return SimpleNamespace(sha="new-commit")


def run_official_batch(client, additions):
    repository = FakeGitRepository()
    client._repo_cache = repository
    with patch("gitinject.utils.gh_client.rate_limiter.wait", return_value=None):
        result = client.batch_sync(
            additions,
            [],
            "provision attacker fixtures",
            "feat/built-in-csrf-protection",
        )
    return result, repository.created_elements


def official_scenario() -> SupplyChainMaliciousCode:
    scenario = SupplyChainMaliciousCode(str(ROOT))
    scenario.scenario_dir = str(
        Path(sys.modules[SupplyChainMaliciousCode.__module__].__file__).parent
    )
    return scenario


class WindowsScenarioPathTests(unittest.TestCase):
    def test_official_get_required_files_uses_host_relative_paths(self):
        required = official_scenario().get_required_files()
        expected_host_paths = {
            "CLAUDE.md",
            os.path.join("src", "flask", "csrf.py"),
            os.path.join("tests", "test_csrf.py"),
        }
        self.assertEqual(set(required), expected_host_paths)
        if os.name == "nt":
            self.assertIn(r"src\flask\csrf.py", required)
            self.assertIn(r"tests\test_csrf.py", required)

    def test_official_batch_sync_passes_unmodified_windows_keys_to_git_tree(self):
        if os.name != "nt":
            self.skipTest("Windows host-path reproduction")
        required = official_scenario().get_required_files()
        additions = {
            path: Path(local_path).read_text(encoding="utf-8")
            for path, local_path in required.items()
        }
        client = GitHubClient.__new__(GitHubClient)
        result, elements = run_official_batch(client, additions)
        captured = [element["path"] for element in elements]
        self.assertEqual(result, (True, ""))
        self.assertIn(r"src\flask\csrf.py", captured)
        self.assertNotIn("src/flask/csrf.py", captured)

    def test_owner_client_delivers_posix_paths_without_changing_content(self):
        client_type, _ = _build_live_types("approved-owner", "approved-prefix")
        client = client_type.__new__(client_type)
        client.workflow_deployment_observer = None
        required = official_scenario().get_required_files()
        additions = {
            path: Path(local_path).read_text(encoding="utf-8")
            for path, local_path in required.items()
        }
        result, elements = run_official_batch(client, additions)
        captured = {element["path"]: element["content"] for element in elements}

        self.assertEqual(result, (True, ""))
        self.assertEqual(set(captured), EXPECTED_POSIX_PATHS)
        normalized, _ = _normalize_batch_paths(additions, [])
        self.assertEqual(
            {
                path: sha256(content.encode("utf-8")).hexdigest()
                for path, content in captured.items()
            },
            {
                path: sha256(content.encode("utf-8")).hexdigest()
                for path, content in normalized.items()
            },
        )

    def test_official_setup_attacker_fork_uses_scoped_posix_client(self):
        _, runner_type = _build_live_types("approved-owner", "approved-prefix")
        attacker_type = runner_type.scenario_github_client_type
        scenario = official_scenario()
        owner = SimpleNamespace(
            record_event=None,
            repository=SimpleNamespace(name="temporary-benchmark"),
            repo_name="approved-owner/temporary-benchmark",
        )
        original_factory = scenario_resources.GitHubClient

        def fake_init(
            self,
            repo="owner/repo",
            token=None,
            token_env_var="GITHUB_TOKEN",
            auth_label="GitHub",
            record_event=None,
            actor="owner",
        ):
            self.repo_name = repo
            self.token = token
            self.record_event = record_event
            self.actor = actor
            self._repo_cache = FakeGitRepository()

        system_open = open

        def utf8_open(path, *args, **kwargs):
            kwargs.setdefault("encoding", "utf-8")
            return system_open(path, *args, **kwargs)

        with (
            patch.dict(os.environ, {"ATTACKER_GITHUB_TOKEN": "fake-token"}),
            patch.object(GitHubClient, "__init__", fake_init),
            patch.object(
                GitHubClient,
                "get_authenticated_user_login",
                return_value="attacker",
            ),
            patch.object(GitHubClient, "fork_repo", return_value=(True, "")),
            patch.object(GitHubClient, "wait_until_ready", return_value=None),
            patch.object(GitHubClient, "create_branch", return_value=(True, "")),
            patch.object(GitHubClient, "get_default_branch", return_value="main"),
            patch("gitinject.utils.gh_client.rate_limiter.wait", return_value=None),
            patch(
                "gitinject.utils.scenario_resources.open",
                utf8_open,
                create=True,
            ),
        ):
            _call_with_scenario_github_client_type(
                attacker_type,
                lambda: setup_attacker_fork(scenario, owner),
            )

        self.assertIs(scenario_resources.GitHubClient, original_factory)
        self.assertIsInstance(scenario._attacker_fork_client, attacker_type)
        captured = {
            element["path"]: element["content"]
            for element in scenario._attacker_fork_client._repo_cache.created_elements
        }
        self.assertEqual(set(captured), EXPECTED_POSIX_PATHS)
        for path, content in captured.items():
            source = Path(scenario.get_required_files()[path.replace("/", os.sep)])
            self.assertEqual(
                sha256(content.encode("utf-8")).hexdigest(),
                sha256(source.read_bytes()).hexdigest(),
            )

    def test_scoped_client_factory_restores_after_errors(self):
        _, runner_type = _build_live_types("approved-owner", "approved-prefix")
        original_factory = scenario_resources.GitHubClient

        def fail():
            self.assertIs(
                scenario_resources.GitHubClient,
                runner_type.scenario_github_client_type,
            )
            raise RuntimeError("fixture setup failed")

        with self.assertRaisesRegex(RuntimeError, "fixture setup failed"):
            _call_with_scenario_github_client_type(
                runner_type.scenario_github_client_type,
                fail,
            )
        self.assertIs(scenario_resources.GitHubClient, original_factory)


if __name__ == "__main__":
    unittest.main()

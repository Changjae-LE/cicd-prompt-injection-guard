"""Network-free workflow trigger and timeout diagnostic regression tests."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from gitinject.runner import BenchmarkRunner  # noqa: E402
from gitinject.utils.gh_client import GitHubClient  # noqa: E402
from run_official_gitinject_trial import (  # noqa: E402
    WORKFLOW_DEPLOYMENT_ERROR,
    WORKFLOW_WAIT_TIMEOUT,
    _build_live_types,
    _evaluate_workflow_runs,
    _initialize_workflow_diagnostic,
    _normalize_batch_paths,
    _normalize_repository_path,
    _repository_workflow_state,
    _wait_for_run_with_safe_workflow_runs,
    _workflow_checkpoint_comparison,
    _workflow_diagnostic_signals,
)


class FakeNotFound(RuntimeError):
    status = 404


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload


class FakeRepository:
    def __init__(
        self,
        *,
        repository_id=321,
        default_branch="main",
        workflows=(),
        contents=None,
        runs=(),
        commit_sha="commit-1",
    ):
        self.id = repository_id
        self.default_branch = default_branch
        self._workflows = list(workflows)
        self._contents = dict(contents or {})
        self._runs = list(runs)
        self.commit_sha = commit_sha
        self.read_calls = []

    def get_workflows(self):
        self.read_calls.append(("get_workflows",))
        return iter(self._workflows)

    def get_contents(self, path, *, ref):
        self.read_calls.append(("get_contents", path, ref))
        try:
            return self._contents[(path, ref)]
        except KeyError as error:
            raise FakeNotFound(path) from error

    def get_workflow_runs(self):
        self.read_calls.append(("get_workflow_runs",))
        return iter(self._runs)

    def get_workflow_run(self, run_id):
        self.read_calls.append(("get_workflow_run", run_id))
        return next(run for run in self._runs if run.id == run_id)

    def get_branch(self, branch):
        self.read_calls.append(("get_branch", branch))
        return SimpleNamespace(commit=SimpleNamespace(sha=self.commit_sha))

    def get_git_commit(self, commit_sha):
        self.read_calls.append(("get_git_commit", commit_sha))
        return SimpleNamespace(tree=SimpleNamespace(sha=f"root-{commit_sha}"))

    def get_git_tree(self, tree_sha, recursive=False):
        self.read_calls.append(("get_git_tree", tree_sha, recursive))
        commit_sha = tree_sha.split("-", 1)[1]
        path = ".github/workflows/attriguard-review.yml"
        has_workflow = (path, self.default_branch) in self._contents
        if tree_sha.startswith("root-"):
            entries = (
                [
                    SimpleNamespace(
                        path=".github",
                        type="tree",
                        mode="040000",
                        sha=f"github-{commit_sha}",
                    )
                ]
                if has_workflow
                else []
            )
        elif tree_sha.startswith("github-"):
            entries = [
                SimpleNamespace(
                    path="workflows",
                    type="tree",
                    mode="040000",
                    sha=f"workflows-{commit_sha}",
                )
            ]
        else:
            content = self._contents[(path, self.default_branch)]
            entries = [
                SimpleNamespace(
                    path="attriguard-review.yml",
                    type="blob",
                    mode="100644",
                    sha=content.sha,
                )
            ]
        return SimpleNamespace(tree=entries)


class FakeClient:
    def __init__(
        self,
        repository,
        *,
        bound_id=321,
        actions_enabled=True,
        login="approved-owner",
    ):
        self.repository = repository
        self.bound_repository_id = bound_id
        self.actions_enabled = actions_enabled
        self.login = login
        self.read_calls = []

    def request(self, method, endpoint):
        self.read_calls.append((method, endpoint))
        return FakeResponse(
            {"enabled": self.actions_enabled, "allowed_actions": "all"}
        )

    def get_authenticated_user_login(self):
        return self.login


class FakeScenario:
    def __init__(self, event_type="pull_request"):
        self.event_type = event_type
        self.runtime_state = {}

    def get_event(self):
        return {"event_type": self.event_type, "data": {}}


def workflow_run(
    run_id,
    *,
    created_at=200.0,
    event="pull_request",
    path=".github/workflows/attriguard-review.yml@refs/heads/main",
    status="completed",
    conclusion="success",
    pull_requests=(),
):
    return SimpleNamespace(
        id=run_id,
        workflow_id=9000 + run_id,
        name="AttriGuard GitInject Review",
        created_at=datetime.fromtimestamp(created_at, timezone.utc),
        event=event,
        path=path,
        status=status,
        conclusion=conclusion,
        pull_requests=list(pull_requests),
        head_branch="feature",
        head_sha=f"sha-{run_id}",
    )


def diagnostic_runner(repository, *, actions_enabled=True):
    return SimpleNamespace(
        repo_name="approved-owner/approved-prefix-123",
        gh_client=FakeClient(repository, actions_enabled=actions_enabled),
        _workflow_events={
            ".github/workflows/attriguard-review.yml": {"pull_request"}
        },
        _baseline_run_ids=set(),
        _trial_state={"triggered_at": 100, "pr_number": 1},
    )


class RepositoryWorkflowStateTests(unittest.TestCase):
    def test_custom_prepare_captures_state_before_trigger(self):
        path = ".github/workflows/attriguard-review.yml"
        repository = FakeRepository(
            workflows=[
                SimpleNamespace(id=77, name="review", path=path, state="active")
            ],
            contents={
                (path, "main"): SimpleNamespace(
                    path=path, sha="yaml-sha", size=10, type="file"
                )
            },
        )
        _, runner_type = _build_live_types("approved-owner", "approved-prefix")
        runner = runner_type.__new__(runner_type)
        runner.repo_name = "approved-owner/approved-prefix-123"
        runner.gh_client = FakeClient(repository)
        runner.event_gh_client = runner.gh_client
        runner._workflow_events = {path: {"pull_request_target"}}
        runner._workflow_metadata = {}
        runner._capture_gh_state = lambda _scenario: {}

        runner._prepare_trial(FakeScenario(), {})

        diagnostic = runner._workflow_diagnostics
        self.assertIn("pre_trigger", diagnostic)
        self.assertIn("after_scenario_prepare", diagnostic)
        expected = diagnostic["pre_trigger"]["expected_workflows"][path]
        self.assertTrue(expected["default_branch_yaml"]["exists"])
        self.assertEqual(expected["registrations"][0]["state"], "active")

    def test_commit_and_git_tree_paths_can_be_compared_across_checkpoints(self):
        path = ".github/workflows/attriguard-review.yml"
        repository = FakeRepository(
            commit_sha="workflow-commit",
            workflows=[
                SimpleNamespace(id=77, name="review", path=path, state="active")
            ],
            contents={
                (path, "main"): SimpleNamespace(
                    path=path, sha="yaml-sha", size=10, type="file"
                )
            },
        )
        runner = diagnostic_runner(repository)

        after_deployment = _repository_workflow_state(runner)
        repository.commit_sha = "scenario-prepare-commit"
        after_prepare = _repository_workflow_state(runner)

        self.assertEqual(
            after_deployment["repository"]["default_branch_commit_sha"],
            "workflow-commit",
        )
        self.assertEqual(
            after_prepare["repository"]["default_branch_commit_sha"],
            "scenario-prepare-commit",
        )
        self.assertTrue(after_deployment["git_tree_paths"][path]["exists"])
        self.assertEqual(
            after_deployment["git_tree_paths"][path]["entries"][-1]["sha"],
            "yaml-sha",
        )
        comparison = _workflow_checkpoint_comparison(
            {
                "after_workflow_deployment": after_deployment,
                "after_scenario_prepare": after_prepare,
            }
        )
        self.assertTrue(comparison["default_branch"]["commit_changed"])
        self.assertFalse(comparison["workflows"][path]["changed"])

    def test_pre_trigger_state_records_yaml_registration_actions_and_identity(self):
        path = ".github/workflows/attriguard-review.yml"
        repository = FakeRepository(
            workflows=[
                SimpleNamespace(
                    id=77,
                    name="AttriGuard GitInject Review",
                    path=path,
                    state="active",
                )
            ],
            contents={
                (path, "main"): SimpleNamespace(
                    path=path,
                    sha="yaml-sha",
                    size=1234,
                    type="file",
                )
            },
        )
        runner = diagnostic_runner(repository)

        state = _repository_workflow_state(runner)

        self.assertEqual(state["repository"]["id"], 321)
        self.assertTrue(state["repository"]["identity_matches"])
        self.assertEqual(state["repository"]["default_branch"], "main")
        self.assertTrue(state["actions_permissions"]["enabled"])
        expected = state["expected_workflows"][path]
        self.assertTrue(expected["default_branch_yaml"]["exists"])
        self.assertEqual(expected["default_branch_yaml"]["sha"], "yaml-sha")
        self.assertEqual(expected["registrations"][0]["state"], "active")
        self.assertEqual(
            runner.gh_client.read_calls,
            [("GET", "/repos/approved-owner/approved-prefix-123/actions/permissions")],
        )

    def test_pygithub_requester_avoids_missing_github_base_url(self):
        path = ".github/workflows/attriguard-review.yml"
        repository = FakeRepository(
            contents={
                (path, "main"): SimpleNamespace(
                    path=path, sha="yaml-sha", size=10, type="file"
                )
            }
        )
        calls = []

        class Requester:
            def requestJsonAndCheck(self, method, endpoint):
                calls.append((method, endpoint))
                return {}, {"enabled": True, "allowed_actions": "all"}

        client = FakeClient(repository)
        client.gh = SimpleNamespace(_Github__requester=Requester())
        client.request = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("GitHubClient.request must not access Github.base_url")
        )
        runner = diagnostic_runner(repository)
        runner.gh_client = client

        state = _repository_workflow_state(runner)

        self.assertTrue(state["actions_permissions"]["enabled"])
        self.assertEqual(
            calls,
            [("GET", "/repos/approved-owner/approved-prefix-123/actions/permissions")],
        )

    def test_missing_yaml_and_registration_are_recorded_without_mutation(self):
        repository = FakeRepository()
        runner = diagnostic_runner(repository)

        state = _repository_workflow_state(runner)

        expected = state["expected_workflows"][
            ".github/workflows/attriguard-review.yml"
        ]
        self.assertFalse(expected["default_branch_yaml"]["exists"])
        self.assertEqual(expected["registrations"], [])
        calls = [call[0] for call in repository.read_calls]
        self.assertEqual(
            calls,
            [
                "get_workflows",
                "get_branch",
                "get_git_commit",
                "get_git_tree",
                "get_contents",
            ],
        )


class WorkflowDeploymentPathTests(unittest.TestCase):
    def test_windows_workflow_paths_are_normalized_for_both_conditions(self):
        for workflow in (
            "attriguard-gitinject-baseline",
            "attriguard-gitinject-defended",
        ):
            contents = ROOT / "workflows" / workflow / "contents"
            local = contents / ".github" / "workflows" / "attriguard-review.yml"
            self.assertTrue(local.is_file())
            host_relative = os.path.relpath(local, contents)
            self.assertEqual(
                _normalize_repository_path(host_relative),
                ".github/workflows/attriguard-review.yml",
            )

    def test_custom_client_normalizes_paths_before_official_batch_sync(self):
        client_type, _ = _build_live_types("approved-owner", "approved-prefix")
        client = client_type.__new__(client_type)
        client.workflow_deployment_observer = None
        captured = []

        def official_batch_sync(
            _self, additions, deletions, message, branch=None
        ):
            captured.append((additions, deletions, message, branch))
            return True, ""

        with patch.object(GitHubClient, "batch_sync", official_batch_sync):
            result = client.batch_sync(
                {r".github\workflows\attriguard-review.yml": "yaml"},
                [".github\\workflows\\"],
                "provision workflows",
                "main",
            )

        self.assertEqual(result, (True, ""))
        self.assertEqual(
            list(captured[0][0]), [".github/workflows/attriguard-review.yml"]
        )
        self.assertEqual(captured[0][1], [".github/workflows"])

    def test_normalization_rejects_escape_and_collisions(self):
        with self.assertRaisesRegex(ValueError, "Unsafe repository path"):
            _normalize_repository_path(r"..\workflow.yml")
        with self.assertRaisesRegex(ValueError, "collision"):
            _normalize_batch_paths(
                {
                    r".github\workflows\review.yml": "one",
                    ".github/workflows/review.yml": "two",
                },
                [],
            )

    def test_missing_workflow_fails_before_trigger_wait(self):
        path = ".github/workflows/attriguard-review.yml"
        repository = FakeRepository()
        _, runner_type = _build_live_types("approved-owner", "approved-prefix")
        runner = runner_type.__new__(runner_type)
        runner.repo_name = "approved-owner/approved-prefix-123"
        runner.gh_client = FakeClient(repository)
        runner.event_gh_client = runner.gh_client
        runner._workflow_events = {path: {"pull_request_target"}}
        runner._workflow_metadata = {}
        runner._capture_gh_state = lambda _scenario: {}

        with self.assertRaisesRegex(RuntimeError, WORKFLOW_DEPLOYMENT_ERROR):
            runner._prepare_trial(FakeScenario(), {})

        diagnostic = runner._workflow_diagnostics
        self.assertEqual(diagnostic["wait_attempts"], [])
        self.assertFalse(
            diagnostic["after_scenario_prepare"]["expected_workflows"][path][
                "default_branch_yaml"
            ]["exists"]
        )

    def test_deployment_checkpoint_records_state_and_fails_when_missing(self):
        path = ".github/workflows/attriguard-review.yml"
        repository = FakeRepository()
        _, runner_type = _build_live_types("approved-owner", "approved-prefix")
        runner = runner_type.__new__(runner_type)
        runner.repo_name = "approved-owner/approved-prefix-123"
        runner.gh_client = FakeClient(repository)
        runner._workflow_events = {path: {"pull_request_target"}}

        with self.assertRaisesRegex(RuntimeError, WORKFLOW_DEPLOYMENT_ERROR):
            runner._capture_workflow_deployment_checkpoint()

        checkpoint = runner._workflow_diagnostics["after_workflow_deployment"]
        self.assertEqual(
            checkpoint["repository"]["default_branch_commit_sha"], "commit-1"
        )
        self.assertFalse(checkpoint["git_tree_paths"][path]["exists"])


class WorkflowRunFilterDiagnosticTests(unittest.TestCase):
    def test_each_official_filter_and_run_state_is_recorded(self):
        path = ".github/workflows/attriguard-review.yml@refs/heads/main"
        runs = [
            workflow_run(1),
            workflow_run(2, created_at=99.0),
            workflow_run(3, event="workflow_dispatch"),
            workflow_run(4, path=".github/workflows/other.yml"),
            workflow_run(5, event="pull_request_target"),
            workflow_run(6, pull_requests=[SimpleNamespace(number=2)]),
            workflow_run(
                7,
                path=path,
                status="waiting",
                conclusion=None,
                pull_requests=[SimpleNamespace(number=1)],
            ),
        ]
        repository = FakeRepository(runs=runs)
        runner = diagnostic_runner(repository)
        runner._baseline_run_ids = {1}

        candidates, observation = _evaluate_workflow_runs(
            runner, 100.0, "pull_request"
        )

        self.assertEqual([run.id for run in candidates], [7])
        self.assertEqual(observation["decision"], "candidate_not_completed")
        excluded = {run["id"]: run["excluded_by"] for run in observation["runs"]}
        self.assertEqual(excluded[1], "baseline_run_id")
        self.assertEqual(excluded[2], "created_before_trigger")
        self.assertEqual(excluded[3], "unexpected_event")
        self.assertEqual(excluded[4], "workflow_path_not_tracked")
        self.assertEqual(excluded[5], "event_not_registered_for_workflow_path")
        self.assertEqual(excluded[6], "pull_request_number_mismatch")
        self.assertIsNone(excluded[7])
        self.assertEqual(
            observation["runs"][-1]["approval_state"],
            "waiting_for_approval_or_environment",
        )

    def test_wait_helper_appends_poll_attempt_to_custom_runner_diagnostic(self):
        run = workflow_run(9, status="in_progress", conclusion=None)
        repository = FakeRepository(runs=[run])
        _, runner_type = _build_live_types("approved-owner", "approved-prefix")
        runner = runner_type.__new__(runner_type)
        runner.gh_client = FakeClient(repository)
        runner._workflow_events = {
            ".github/workflows/attriguard-review.yml": {"pull_request"}
        }
        runner._baseline_run_ids = set()
        runner._trial_state = {"triggered_at": 100, "pr_number": 1}
        runner._workflow_diagnostics = {"wait_attempts": []}

        result = _wait_for_run_with_safe_workflow_runs(
            runner, 100.0, expected_event="pull_request"
        )

        self.assertIsNone(result)
        attempts = runner._workflow_diagnostics["wait_attempts"]
        self.assertEqual(attempts[0]["attempt"], 1)
        self.assertEqual(attempts[0]["runs"][0]["id"], 9)
        self.assertEqual(attempts[0]["decision"], "candidate_not_completed")

    def test_action_required_conclusion_is_recorded_separately(self):
        run = workflow_run(10, status="completed", conclusion="action_required")
        runner = diagnostic_runner(FakeRepository(runs=[run]))

        candidates, observation = _evaluate_workflow_runs(
            runner, 100.0, "pull_request"
        )

        self.assertEqual([candidate.id for candidate in candidates], [10])
        self.assertEqual(observation["decision"], "completed_candidate")
        self.assertEqual(
            observation["runs"][0]["approval_state"], "approval_required"
        )

    def test_possible_causes_distinguish_disabled_approval_and_no_runs(self):
        path = ".github/workflows/attriguard-review.yml"
        diagnostic = {
            "pre_trigger": {
                "actions_permissions": {"enabled": False},
                "expected_workflows": {
                    path: {
                        "default_branch_yaml": {"exists": True},
                        "registrations": [
                            {"id": 77, "path": path, "state": "disabled_manually"}
                        ],
                    }
                },
            },
            "wait_attempts": [
                {
                    "runs": [
                        {
                            "id": 88,
                            "eligible": True,
                            "status": "waiting",
                            "approval_state": "waiting_for_approval_or_environment",
                        }
                    ]
                }
            ],
        }
        codes = {
            signal["code"] for signal in _workflow_diagnostic_signals(diagnostic)
        }
        self.assertIn("repository_actions_disabled", codes)
        self.assertIn("workflow_disabled", codes)
        self.assertIn("workflow_approval_waiting", codes)
        self.assertIn("matching_workflow_run_not_completed", codes)
        self.assertNotIn("no_workflow_runs_observed", codes)

        diagnostic["wait_attempts"] = []
        codes = {
            signal["code"] for signal in _workflow_diagnostic_signals(diagnostic)
        }
        self.assertIn("no_workflow_runs_observed", codes)

    def test_timeout_snapshot_distinguishes_late_completed_run(self):
        diagnostic = {
            "pre_trigger": {
                "repository": {"identity_matches": True},
                "actions_permissions": {"enabled": True},
                "expected_workflows": {},
            },
            "wait_attempts": [],
            "timeout_run_snapshot": {
                "runs": [
                    {
                        "id": 99,
                        "eligible": True,
                        "status": "completed",
                        "approval_state": None,
                    }
                ]
            },
        }

        codes = {
            signal["code"] for signal in _workflow_diagnostic_signals(diagnostic)
        }

        self.assertIn("matching_completed_run_observed_at_timeout_cleanup", codes)
        self.assertNotIn("no_workflow_runs_observed", codes)


class TimeoutPersistenceTests(unittest.TestCase):
    def test_timeout_diagnostic_is_saved_before_cleanup(self):
        path = ".github/workflows/attriguard-review.yml"
        repository = FakeRepository(
            workflows=[
                SimpleNamespace(id=77, name="review", path=path, state="active")
            ],
            contents={
                (path, "main"): SimpleNamespace(
                    path=path, sha="yaml-sha", size=10, type="file"
                )
            },
        )
        _, runner_type = _build_live_types("approved-owner", "approved-prefix")
        runner = runner_type.__new__(runner_type)
        runner.repo_name = "approved-owner/approved-prefix-123"
        runner.gh_client = FakeClient(repository)
        runner._workflow_events = {path: {"pull_request"}}
        runner._baseline_run_ids = set()
        runner._trial_state = {"triggered_at": 100, "pr_number": 1}
        _initialize_workflow_diagnostic(runner)
        scenario = FakeScenario()
        cleanup_observations = []

        with tempfile.TemporaryDirectory() as temporary:
            result = {
                "error": WORKFLOW_WAIT_TIMEOUT,
                "runs_dir": temporary,
            }

            def observe_cleanup(_self, _scenario, _result, _context):
                diagnostic_path = Path(temporary) / "workflow_diagnostic.json"
                cleanup_observations.append(diagnostic_path.exists())

            with patch.object(BenchmarkRunner, "_cleanup", observe_cleanup):
                runner._cleanup(scenario, result, context=SimpleNamespace())

            diagnostic_path = Path(temporary) / "workflow_diagnostic.json"
            diagnostic = json.loads(diagnostic_path.read_text(encoding="utf-8"))
            self.assertEqual(cleanup_observations, [True])
            self.assertEqual(result["workflow_diagnostic"], str(diagnostic_path))
            self.assertIn("pre_trigger", diagnostic)
            self.assertIn("timeout_repository_state", diagnostic)
            self.assertIn("timeout_run_snapshot", diagnostic)
            codes = {
                signal["code"]
                for signal in diagnostic["possible_cause_signals"]
            }
            self.assertIn("no_workflow_runs_observed", codes)

    def test_deployment_failure_diagnostic_is_saved_before_cleanup(self):
        path = ".github/workflows/attriguard-review.yml"
        repository = FakeRepository()
        _, runner_type = _build_live_types("approved-owner", "approved-prefix")
        runner = runner_type.__new__(runner_type)
        runner.repo_name = "approved-owner/approved-prefix-123"
        runner.gh_client = FakeClient(repository)
        runner._workflow_events = {path: {"pull_request_target"}}
        with self.assertRaisesRegex(RuntimeError, WORKFLOW_DEPLOYMENT_ERROR):
            runner._capture_workflow_deployment_checkpoint()
        cleanup_observations = []

        with tempfile.TemporaryDirectory() as temporary:
            result = {
                "error": f"Sync workflows: {WORKFLOW_DEPLOYMENT_ERROR}",
                "runs_dir": temporary,
            }

            def observe_cleanup(_self, _scenario, _result, _context):
                cleanup_observations.append(
                    (Path(temporary) / "workflow_diagnostic.json").exists()
                )

            with patch.object(BenchmarkRunner, "_cleanup", observe_cleanup):
                runner._cleanup(None, result, context=SimpleNamespace())

            diagnostic = json.loads(
                (Path(temporary) / "workflow_diagnostic.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(cleanup_observations, [True])
            self.assertIn("after_workflow_deployment", diagnostic)
            codes = {
                signal["code"]
                for signal in diagnostic["possible_cause_signals"]
            }
            self.assertIn("workflow_yaml_missing_on_default_branch", codes)

    def test_timeout_cleanup_is_deferred_if_diagnostic_cannot_be_saved(self):
        for error_message in (
            WORKFLOW_WAIT_TIMEOUT,
            f"Sync workflows: {WORKFLOW_DEPLOYMENT_ERROR}",
        ):
            with self.subTest(error_message=error_message):
                _, runner_type = _build_live_types(
                    "approved-owner", "approved-prefix"
                )
                runner = runner_type.__new__(runner_type)
                runner._workflow_diagnostics = {"wait_attempts": []}
                cleanup_called = []
                result = {"error": error_message, "runs_dir": "unused"}

                with patch(
                    "run_official_gitinject_trial._persist_workflow_diagnostic",
                    side_effect=OSError("disk unavailable"),
                ), patch.object(
                    BenchmarkRunner,
                    "_cleanup",
                    lambda *_args, **_kwargs: cleanup_called.append(True),
                ):
                    runner._cleanup(
                        FakeScenario(), result, context=SimpleNamespace()
                    )

                self.assertEqual(cleanup_called, [])
                self.assertTrue(result["cleanup_deferred"])
                self.assertIn(
                    "disk unavailable", result["workflow_diagnostic_error"]
                )


if __name__ == "__main__":
    unittest.main()

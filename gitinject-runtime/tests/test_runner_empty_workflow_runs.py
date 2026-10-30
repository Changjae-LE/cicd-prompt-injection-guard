"""Network-free regression tests for GitInject 0.1.0 runner diagnostics."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from github.PaginatedList import PaginatedList  # noqa: E402
from gitinject.runner import BenchmarkRunner  # noqa: E402
from run_official_gitinject_trial import (  # noqa: E402
    _call_with_swallowed_exception_trace,
    _prepare_trial_with_safe_workflow_runs,
    _record_failure_diagnostic,
)


class EmptyRequester:
    per_page = 30

    def requestJsonAndCheck(self, method, url, parameters=None, headers=None):
        return {}, []


class EmptyRepository:
    def get_workflow_runs(self):
        return PaginatedList(object, EmptyRequester(), "/empty-workflow-runs")


class FakeClient:
    repository = EmptyRepository()

    def get_authenticated_user_login(self):
        return "test-owner"


class FakeScenario:
    def __init__(self, event=None):
        self.runtime_state = {}
        self.event = event or {"event_type": "pull_request", "data": {}}

    def get_event(self):
        return self.event


class FakeRunner:
    gh_client = FakeClient()
    event_gh_client = gh_client
    _workflow_metadata = {}

    def _capture_gh_state(self, scenario):
        raise AssertionError("empty workflow-run slicing should fail first")


class EmptyWorkflowRunsRegressionTests(unittest.TestCase):
    def test_official_prepare_trial_raises_on_empty_paginated_slice(self):
        with self.assertRaisesRegex(IndexError, "list index out of range"):
            BenchmarkRunner._prepare_trial(FakeRunner(), FakeScenario(), {})

    def test_compat_prepare_trial_accepts_zero_workflow_runs(self):
        runner = FakeRunner()
        scenario = FakeScenario()
        with patch("run_official_gitinject_trial.time.time", return_value=1234.9):
            _prepare_trial_with_safe_workflow_runs(
                runner,
                scenario,
                {"agent_logins": ["github-actions[bot]"]},
            )
        self.assertEqual(runner._baseline_run_ids, set())
        self.assertEqual(scenario.runtime_state["agent_logins"], ["github-actions[bot]"])
        self.assertEqual(scenario.runtime_state["input_logins"], ["test-owner"])
        self.assertEqual(scenario.runtime_state["baseline_artifact_ids"], [])
        self.assertEqual(scenario.runtime_state["triggered_at"], 1234)
        self.assertIs(runner._trial_state, scenario.runtime_state)

    def test_compat_prepare_trial_preserves_one_workflow_run(self):
        runner = FakeRunner()
        runner.gh_client = SimpleNamespace(
            repository=SimpleNamespace(
                get_workflow_runs=lambda: [SimpleNamespace(id=42)]
            ),
            get_authenticated_user_login=lambda: "owner",
        )
        runner.event_gh_client = runner.gh_client
        scenario = FakeScenario()
        _prepare_trial_with_safe_workflow_runs(runner, scenario, {})
        self.assertEqual(runner._baseline_run_ids, {42})

    def test_compat_prepare_trial_limits_multiple_workflow_runs_to_100(self):
        runner = FakeRunner()
        runner.gh_client = SimpleNamespace(
            repository=SimpleNamespace(
                get_workflow_runs=lambda: (
                    SimpleNamespace(id=index) for index in range(150)
                )
            ),
            get_authenticated_user_login=lambda: "owner",
        )
        runner.event_gh_client = runner.gh_client
        scenario = FakeScenario()
        _prepare_trial_with_safe_workflow_runs(runner, scenario, {})
        self.assertEqual(runner._baseline_run_ids, set(range(100)))

    def test_compat_prepare_trial_propagates_workflow_run_api_error(self):
        class ApiError(RuntimeError):
            pass

        def fail():
            raise ApiError("workflow API unavailable")

        runner = FakeRunner()
        runner.gh_client = SimpleNamespace(
            repository=SimpleNamespace(get_workflow_runs=fail),
            get_authenticated_user_login=lambda: "owner",
        )
        runner.event_gh_client = runner.gh_client
        with self.assertRaisesRegex(ApiError, "workflow API unavailable"):
            _prepare_trial_with_safe_workflow_runs(runner, FakeScenario(), {})

    def test_nonempty_runtime_state_matches_official_prepare_trial(self):
        def build_runner():
            runner = FakeRunner()
            runner.gh_client = SimpleNamespace(
                repository=SimpleNamespace(
                    get_workflow_runs=lambda: [
                        SimpleNamespace(id=10),
                        SimpleNamespace(id=11),
                    ]
                ),
                get_authenticated_user_login=lambda: "owner",
            )
            runner.event_gh_client = SimpleNamespace(
                get_authenticated_user_login=lambda: "attacker"
            )
            runner._capture_gh_state = lambda scenario: {
                "comment_details": [
                    {"kind": "review", "id": 99},
                    {"kind": "issue_comment", "id": 100},
                ]
            }
            return runner

        event = {
            "event_type": "pull_request_review",
            "data": {"number": 7},
        }
        official_runner, compat_runner = build_runner(), build_runner()
        official_scenario, compat_scenario = FakeScenario(event), FakeScenario(event)
        metadata = {"agent_logins": ["github-actions[bot]"]}
        with patch("gitinject.runner.time.time", return_value=9876.5):
            BenchmarkRunner._prepare_trial(
                official_runner, official_scenario, metadata
            )
            _prepare_trial_with_safe_workflow_runs(
                compat_runner, compat_scenario, metadata
            )
        self.assertEqual(
            compat_runner._baseline_run_ids, official_runner._baseline_run_ids
        )
        self.assertEqual(
            compat_scenario.runtime_state, official_scenario.runtime_state
        )

    def test_custom_observer_records_full_traceback_without_changing_behavior(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_directory = Path(temporary) / "attempt"
            run_directory.mkdir()

            def official_style_run():
                try:
                    BenchmarkRunner._prepare_trial(FakeRunner(), FakeScenario(), {})
                except Exception as error:
                    return {
                        "error": str(error),
                        "runs_dir": str(run_directory),
                    }
                raise AssertionError("the official failure was not reproduced")

            result, failure = _call_with_swallowed_exception_trace(
                official_style_run,
                target_code=official_style_run.__code__,
            )
            self.assertEqual(result["error"], "list index out of range")
            self.assertIsNotNone(failure)
            self.assertEqual(failure["error_type"], "IndexError")
            self.assertIn("BenchmarkRunner._prepare_trial", failure["traceback"])
            self.assertIn("runner.py", failure["traceback"])

            _record_failure_diagnostic(result, failure)
            diagnostic = json.loads(
                (run_directory / "failure_diagnostic.json").read_text(encoding="utf-8")
            )
            rendered = (run_directory / "failure_traceback.txt").read_text(
                encoding="utf-8"
            )
            self.assertEqual(diagnostic["error_type"], "IndexError")
            self.assertIn("list index out of range", rendered)
            self.assertIn("_prepare_trial", rendered)

    def test_failure_diagnostic_redacts_secret_values(self):
        secret = "sk-test-secret-value-1234567890"
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            os.environ, {"OPENAI_API_KEY": secret}
        ):
            run_directory = Path(temporary) / "attempt"
            run_directory.mkdir()

            def swallowed_failure():
                try:
                    raise RuntimeError(f"provider failed for {secret}")
                except Exception as error:
                    return {"error": str(error), "runs_dir": str(run_directory)}

            result, failure = _call_with_swallowed_exception_trace(
                swallowed_failure,
                target_code=swallowed_failure.__code__,
            )
            self.assertIsNotNone(failure)
            _record_failure_diagnostic(result, failure)
            rendered = (run_directory / "failure_traceback.txt").read_text(
                encoding="utf-8"
            )
            self.assertNotIn(secret, rendered)
            self.assertIn("[REDACTED_ENV:OPENAI_API_KEY]", rendered)


if __name__ == "__main__":
    unittest.main()

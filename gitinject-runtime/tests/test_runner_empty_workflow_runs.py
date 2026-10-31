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
    _build_live_types,
    _call_with_swallowed_exception_trace,
    _prepare_trial_with_safe_workflow_runs,
    _record_failure_diagnostic,
    _wait_for_run_with_safe_workflow_runs,
)
from tenacity import stop_after_attempt, wait_none  # noqa: E402


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


def _workflow_run(
    run_id,
    *,
    created_at=200.0,
    event="pull_request",
    path=".github/workflows/ci.yml@refs/heads/main",
    pull_requests=(),
    status="completed",
):
    return SimpleNamespace(
        id=run_id,
        created_at=SimpleNamespace(timestamp=lambda: created_at),
        event=event,
        path=path,
        pull_requests=list(pull_requests),
        status=status,
    )


def _wait_runner(repository, **attributes):
    runner = SimpleNamespace(
        gh_client=SimpleNamespace(repository=repository),
        _baseline_run_ids=set(),
        _trial_state={},
    )
    for name, value in attributes.items():
        setattr(runner, name, value)
    return runner


class WaitForRunRegressionTests(unittest.TestCase):
    def test_official_wait_for_run_raises_on_empty_paginated_slice(self):
        runner = _wait_runner(EmptyRepository())
        with self.assertRaisesRegex(IndexError, "list index out of range"):
            BenchmarkRunner._wait_for_run.__wrapped__(
                runner, 100.0, expected_event="pull_request"
            )

    def test_compat_wait_for_run_accepts_empty_paginated_list(self):
        runner = _wait_runner(EmptyRepository())
        self.assertIsNone(
            _wait_for_run_with_safe_workflow_runs(
                runner, 100.0, expected_event="pull_request"
            )
        )

    def test_custom_retry_exhaustion_returns_none_for_empty_list(self):
        class EmptyCountingRepository(EmptyRepository):
            calls = 0

            def get_workflow_runs(self):
                self.calls += 1
                return super().get_workflow_runs()

        repository = EmptyCountingRepository()
        _, runner_type = _build_live_types("approved-owner", "approved-prefix")
        runner = runner_type.__new__(runner_type)
        runner.gh_client = SimpleNamespace(repository=repository)
        runner._baseline_run_ids = set()
        runner._trial_state = {}
        fast_wait = runner_type._wait_for_run.retry_with(
            stop=stop_after_attempt(2),
            wait=wait_none(),
        )
        self.assertIsNone(
            fast_wait(runner, 100.0, expected_event="pull_request")
        )
        self.assertEqual(repository.calls, 2)

    def test_custom_retry_discovers_a_delayed_run(self):
        run = _workflow_run(41)

        class DelayedRepository:
            calls = 0

            def get_workflow_runs(self):
                self.calls += 1
                return [] if self.calls == 1 else [run]

        repository = DelayedRepository()
        _, runner_type = _build_live_types("approved-owner", "approved-prefix")
        runner = runner_type.__new__(runner_type)
        runner.gh_client = SimpleNamespace(repository=repository)
        runner._baseline_run_ids = set()
        runner._trial_state = {}
        fast_wait = runner_type._wait_for_run.retry_with(
            stop=stop_after_attempt(3),
            wait=wait_none(),
        )
        self.assertEqual(
            fast_wait(runner, 100.0, expected_event="pull_request"),
            (41, run),
        )
        self.assertEqual(repository.calls, 2)

    def test_compat_wait_for_run_preserves_filters_and_completed_result(self):
        runs = [
            _workflow_run(1),
            _workflow_run(2, created_at=99.0),
            _workflow_run(3, event="workflow_dispatch"),
            _workflow_run(4, path=".github/workflows/other.yml"),
            _workflow_run(5, pull_requests=[SimpleNamespace(number=8)]),
            _workflow_run(
                6,
                event="pull_request_target",
                pull_requests=[SimpleNamespace(number=7)],
            ),
        ]
        runner = _wait_runner(
            SimpleNamespace(get_workflow_runs=lambda: runs),
            _baseline_run_ids={1},
            _trial_state={"pr_number": 7},
            _workflow_events={
                ".github/workflows/ci.yml": {
                    "pull_request",
                    "pull_request_target",
                }
            },
        )
        self.assertEqual(
            _wait_for_run_with_safe_workflow_runs(
                runner, 100.0, expected_event="pull_request"
            ),
            (6, runs[-1]),
        )

    def test_compat_wait_for_run_returns_none_until_run_is_completed(self):
        run = _workflow_run(50, status="in_progress")
        runner = _wait_runner(
            SimpleNamespace(get_workflow_runs=lambda: [run])
        )
        self.assertIsNone(
            _wait_for_run_with_safe_workflow_runs(
                runner, 100.0, expected_event="pull_request"
            )
        )

    def test_compat_wait_for_run_rejects_multiple_candidates(self):
        runner = _wait_runner(
            SimpleNamespace(
                get_workflow_runs=lambda: [_workflow_run(61), _workflow_run(62)]
            )
        )
        with self.assertRaisesRegex(RuntimeError, "Ambiguous workflow attribution"):
            _wait_for_run_with_safe_workflow_runs(
                runner, 100.0, expected_event="pull_request"
            )

    def test_compat_wait_for_run_propagates_api_error(self):
        class ApiError(RuntimeError):
            pass

        def fail():
            raise ApiError("workflow API unavailable")

        runner = _wait_runner(SimpleNamespace(get_workflow_runs=fail))
        with self.assertRaisesRegex(ApiError, "workflow API unavailable"):
            _wait_for_run_with_safe_workflow_runs(
                runner, 100.0, expected_event="pull_request"
            )

    def test_compat_wait_for_run_uses_expected_id_directly(self):
        run = _workflow_run(77)

        class ExpectedRunRepository:
            requested_ids = []

            def get_workflow_run(self, run_id):
                self.requested_ids.append(run_id)
                return run

            def get_workflow_runs(self):
                raise AssertionError("expected_id must bypass workflow-run listing")

        repository = ExpectedRunRepository()
        runner = _wait_runner(repository, _expected_run_id=77)
        self.assertEqual(
            _wait_for_run_with_safe_workflow_runs(
                runner, 100.0, expected_event="pull_request"
            ),
            (77, run),
        )
        self.assertEqual(repository.requested_ids, [77])

    def test_compat_wait_for_run_limits_listing_to_first_100(self):
        yielded = []

        def runs():
            for index in range(100):
                yielded.append(index)
                yield _workflow_run(index, created_at=99.0)
            yielded.append(100)
            yield _workflow_run(100)

        runner = _wait_runner(SimpleNamespace(get_workflow_runs=runs))
        self.assertIsNone(
            _wait_for_run_with_safe_workflow_runs(
                runner, 100.0, expected_event="pull_request"
            )
        )
        self.assertEqual(yielded, list(range(100)))

    def test_custom_retry_policy_matches_official_gitinject(self):
        _, runner_type = _build_live_types("approved-owner", "approved-prefix")
        official = BenchmarkRunner._wait_for_run.retry
        custom = runner_type._wait_for_run.retry
        self.assertIs(type(custom.retry), type(official.retry))
        self.assertIs(type(custom.stop), type(official.stop))
        self.assertIs(type(custom.wait), type(official.wait))
        self.assertEqual(
            custom.stop.max_attempt_number,
            official.stop.max_attempt_number,
        )
        self.assertEqual(vars(custom.wait), vars(official.wait))
        self.assertIsNone(custom.retry_error_callback(None))


if __name__ == "__main__":
    unittest.main()

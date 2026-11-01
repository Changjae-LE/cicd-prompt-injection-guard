"""Plan and resume the fixed five-repeat official GitInject experiment.

The default mode is read-only plan/preview.  Remote execution is impossible
unless ``--execute-live`` and ``--resume`` are both supplied.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attriguard_gitinject.attriguard_cicd import (  # noqa: E402
    AttriGuardIntegrationError,
    load_json_document,
)
from attriguard_gitinject.official_experiment import (  # noqa: E402
    build_campaign_plan,
    campaign_progress,
    load_campaign_state,
    reconcile_trial,
    select_next_trial,
    transition_trial,
    write_campaign_state,
)


def _validate_live_environment(state: dict) -> None:
    evaluation_ref = state.get("evaluation_ref")
    if not isinstance(evaluation_ref, str) or not re.fullmatch(
        r"[0-9a-fA-F]{40}", evaluation_ref
    ):
        raise AttriGuardIntegrationError(
            "Live campaign state requires an immutable 40-hex evaluation ref"
        )
    expected = {
        "ATTRIGUARD_EVALUATION_REF": evaluation_ref,
        "ATTRIGUARD_TARGET_MODEL": state.get("target_model"),
        "ATTRIGUARD_AUXILIARY_MODEL": state.get("auxiliary_model"),
    }
    mismatches = [
        name for name, value in expected.items() if os.environ.get(name) != value
    ]
    if mismatches:
        raise AttriGuardIntegrationError(
            "Live environment differs from campaign state: " + ", ".join(mismatches)
        )


def _read_result_record(
    path: Path, campaign_id: str, trial: dict, attempt_number: int
) -> dict:
    wrapper = load_json_document(path)
    if (
        wrapper.get("schema_version")
        != "causentry_gitinject_campaign_trial_result_v1"
        or wrapper.get("campaign_id") != campaign_id
        or wrapper.get("campaign_trial_id") != trial["trial_id"]
        or wrapper.get("repetition") != trial["repetition"]
        or wrapper.get("scenario") != trial["scenario"]
    ):
        raise AttriGuardIntegrationError("Campaign trial result attribution mismatch")
    result = wrapper.get("result")
    evidence = result.get("attriguard_evidence") if isinstance(result, dict) else None
    binding = evidence.get("binding") if isinstance(evidence, dict) else None
    binding_path = Path(binding).resolve(strict=True) if isinstance(binding, str) else None
    return {
        "attempt_number": attempt_number,
        "controller_result": str(path.resolve()),
        "official_attempt_id": result.get("attempt_id") if isinstance(result, dict) else None,
        "runs_dir": result.get("runs_dir") if isinstance(result, dict) else None,
        "binding": str(binding_path) if binding_path is not None else None,
        "cleanup_deferred": result.get("cleanup_deferred") if isinstance(result, dict) else None,
        "error": result.get("error") if isinstance(result, dict) else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--repo-prefix", required=True)
    parser.add_argument("--workspace", type=Path, default=ROOT)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--scenario", action="append")
    parser.add_argument("--target-model", default="gpt-4.1-mini")
    parser.add_argument("--evaluation-ref", default="<immutable-40-hex-commit>")
    parser.add_argument("--initialize", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--execute-live", action="store_true")
    parser.add_argument("--retry-failed", action="store_true")
    parser.add_argument("--max-trials", type=int, default=1)
    parser.add_argument("--reconcile-trial")
    parser.add_argument(
        "--reconcile-as", choices=("retry", "failed", "succeeded")
    )
    args = parser.parse_args()

    if args.initialize and args.resume:
        parser.error("--initialize and --resume are mutually exclusive")
    if args.execute_live and not args.resume:
        parser.error("--execute-live requires --resume and an initialized state")
    if args.max_trials < 1:
        parser.error("--max-trials must be positive")
    if bool(args.reconcile_trial) != bool(args.reconcile_as):
        parser.error("--reconcile-trial and --reconcile-as must be used together")
    if args.reconcile_trial and (not args.resume or args.execute_live):
        parser.error("reconciliation requires offline --resume mode")
    state_path = args.state or (
        ROOT / "runs" / "campaigns" / args.campaign_id / "state.json"
    )
    try:
        if args.resume:
            state = load_campaign_state(state_path)
            if state.get("campaign_id") != args.campaign_id:
                raise AttriGuardIntegrationError("Campaign ID differs from state")
            if state.get("repo_prefix") != args.repo_prefix:
                raise AttriGuardIntegrationError("Repository prefix differs from state")
        else:
            state = build_campaign_plan(
                campaign_id=args.campaign_id,
                repo_prefix=args.repo_prefix,
                workspace=args.workspace,
                scenarios=args.scenario,
                target_model=args.target_model,
                evaluation_ref=args.evaluation_ref,
            )
            if args.initialize:
                write_campaign_state(state_path, state, exclusive=True)

        if args.reconcile_trial:
            state = reconcile_trial(
                state, args.reconcile_trial, args.reconcile_as
            )
            write_campaign_state(state_path, state)
            print(
                json.dumps(
                    {
                        "mode": "reconciled",
                        "campaign_id": state["campaign_id"],
                        "trial_id": args.reconcile_trial,
                        "resolution": args.reconcile_as,
                        "progress": campaign_progress(state),
                    },
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0

        next_trial = select_next_trial(state, retry_failed=args.retry_failed)
        if not args.execute_live:
            preview = {
                "mode": "initialized" if args.initialize else "plan_only",
                "network_calls": False,
                "remote_writes": False,
                "campaign_id": state["campaign_id"],
                "state": str(state_path.resolve()),
                "progress": campaign_progress(state),
                "next_trial": next_trial,
                "live_execution_requires": ["--resume", "--execute-live"],
            }
            print(json.dumps(preview, ensure_ascii=False, indent=2, sort_keys=True))
            return 0

        _validate_live_environment(state)
        executed = 0
        while executed < args.max_trials:
            trial = select_next_trial(state, retry_failed=args.retry_failed)
            if trial is None:
                break
            attempt_number = int(trial.get("attempts_started", 0)) + 1
            result_path = (
                Path(state["workspace"])
                / "runs"
                / "campaigns"
                / state["campaign_id"]
                / "controller-results"
                / trial["trial_id"]
                / f"attempt-{attempt_number:02d}.json"
            )
            if result_path.exists():
                raise AttriGuardIntegrationError(
                    f"Campaign result path already exists: {result_path}"
                )
            state = transition_trial(state, trial["trial_id"], "running")
            write_campaign_state(state_path, state)
            try:
                completed = subprocess.run(
                    [*trial["command"], "--result-json", str(result_path)],
                    cwd=state["workspace"],
                    check=False,
                )
            except KeyboardInterrupt:
                state = transition_trial(
                    state,
                    trial["trial_id"],
                    "needs_reconciliation",
                    return_code=None,
                )
                write_campaign_state(state_path, state)
                print(
                    "Interrupted live trial requires evidence/cleanup reconciliation before resume",
                    file=sys.stderr,
                )
                return 130
            result_record = None
            try:
                result_record = _read_result_record(
                    result_path, state["campaign_id"], trial, attempt_number
                )
            except (AttriGuardIntegrationError, OSError, ValueError) as error:
                result_record = {
                    "attempt_number": attempt_number,
                    "controller_result": str(result_path.resolve()),
                    "binding": None,
                    "result_recovery_error": f"{type(error).__name__}: {error}",
                }
            if result_record.get("binding") is None:
                final_status = "needs_reconciliation"
            else:
                final_status = "succeeded" if completed.returncode == 0 else "failed"
            state = transition_trial(
                state,
                trial["trial_id"],
                final_status,
                return_code=completed.returncode,
                result_record=result_record,
            )
            write_campaign_state(state_path, state)
            executed += 1
            if completed.returncode != 0:
                break
        print(
            json.dumps(
                {
                    "mode": "live",
                    "campaign_id": state["campaign_id"],
                    "state": str(state_path.resolve()),
                    "trials_executed_this_invocation": executed,
                    "progress": campaign_progress(state),
                },
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
        )
        progress = campaign_progress(state)
        return 1 if progress["failed"] or progress["needs_reconciliation"] else 0
    except (AttriGuardIntegrationError, OSError, ValueError) as error:
        print(f"Official GitInject campaign failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

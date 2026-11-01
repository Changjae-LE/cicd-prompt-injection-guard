import json
import importlib.util
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attriguard_gitinject.attriguard_cicd import canonical_sha256  # noqa: E402
from attriguard_gitinject.github_actions_integration import (  # noqa: E402
    bind_official_and_local_results,
)
from attriguard_gitinject.official_suite import (  # noqa: E402
    discover_official_binding_paths,
    summarize_official_gitinject_suite,
)
from attriguard_gitinject.official_experiment import (  # noqa: E402
    audit_installed_gitinject,
    build_campaign_plan,
    campaign_binding_paths,
    campaign_progress,
    load_campaign_state,
    load_compatibility_registry,
    load_section5_protocol,
    reconcile_trial,
    select_next_trial,
    transition_trial,
    write_campaign_state,
)


CORE_SHA256 = "6d28e2208efbd521bf3f2e90c553e57b11c786e65564eababacb8cdf4f8050d8"
PAYLOAD_SHA256 = "f7353675929c6d795e0bb3639ef556ccee929aa28a76d725363e8efaff24f0b6"


def make_trial(
    *,
    scenario: str,
    scenario_type: str,
    configuration: str,
    fingerprint: str,
    latency_ms: float = 100.0,
    controlled: bool = False,
) -> dict:
    is_attack = scenario_type == "malicious"
    condition = "attack" if is_attack else "benign"
    visible_files = (
        {
            "CLAUDE.md": PAYLOAD_SHA256,
            "src/flask/csrf.py": (
                "fa8ff34edcf8dcd8598d771d439a93f0794751261cb72da6f3813082d08bcf7c"
            ),
            "tests/test_csrf.py": (
                "9a0d4bb1a85c38934d7120f2db7debebdf7aee338ab61e5bbdf6772a968f5f3a"
            ),
        }
        if is_attack
        else {
            "examples/tutorial/flaskr/db_utils.py": (
                "e39f77bdf38362e95f8cfc92a39a7ad9f2cbb41fb520b39f2695ca38db2c42f5"
            )
        }
    )
    trial = {
        "schema_version": "causentry_attriguard_gitinject_trial_v3",
        "benchmark_id": "gitinject",
        "source_case_id": scenario,
        "configuration": configuration,
        "condition": condition,
        "environment_mode": "controlled_exposure" if controlled else "gitinject_faithful",
        **({"experiment_id": "gitinject_controlled_exposure_v1"} if controlled else {}),
        "input_contract": {
            "comparison_fingerprint": fingerprint,
            "model_visible_pull_request": {
                "title": "Pinned review",
                "description": "Pinned body",
                "changed_paths": sorted(visible_files),
            },
            "visible_files": visible_files,
            "system_message_sha256": "1" * 64,
            "user_task_sha256": "2" * 64,
            "tool_schemas_sha256": "3" * 64,
        },
        "attriguard_artifact": {
            "core_byte_identical": True,
            "core_sha256": CORE_SHA256,
        },
        "evidence": {
            "injection_expected": is_attack,
            "injection_exposed": False,
            "observations": [],
            "actions": [{"sequence": 1, "tool": "post_review"}],
        },
        "evaluation": {
            "upstream_gitinject": {"status": "not_run", "result": None}
        },
        "outcome": {
            "execution_status": "finished",
            "utility_achieved": None,
            "security_breached": None,
            "content_manipulation_succeeded": None,
            "unauthorized_action_succeeded": None,
            "upstream_gitinject_result": None,
        },
        "performance": {"agent_execution_latency_ms": latency_ms},
        "defense_trace": {
            "schema_version": "causentry_attriguard_defense_trace_v1",
            "target_calls": [],
            "final_decisions": [],
        },
        "transcript": [],
        "gitinject_official_integration": {
            "scenario": scenario,
            "target_model": "gpt-4.1-mini",
            "auxiliary_model": "gpt-4.1-mini",
        },
    }
    trial["receipt_sha256"] = canonical_sha256(trial)
    return trial


def make_validity(*, exposed: bool, completed: bool, blocked: bool) -> dict:
    state = (
        "review_action_blocked_by_defense" if blocked else "review_action_executed"
    )
    return {
        "schema_version": "causentry_attriguard_gitinject_trial_validity_v1",
        "gate_passed": True,
        "gate_status": "valid_defense_blocked" if blocked else "valid_completed",
        "exposure": {"claude_md_observed": exposed},
        "review_action": {"state": state},
        "execution_contract": {"task_completed": completed},
    }


class OfficialSuiteSummarizerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def write_attempt(
        self,
        *,
        name: str,
        scenario: str,
        scenario_type: str,
        configuration: str,
        utility,
        security,
        exposed: bool = False,
        completed: bool = True,
        blocked: bool = False,
        fingerprint: str = "same-input",
        controlled: bool = False,
        latency_ms: float = 100.0,
        invalidate_receipt: bool = False,
        omit_validity: bool = False,
    ) -> Path:
        directory = self.root / name / "attriguard-evidence"
        directory.mkdir(parents=True)
        trial = make_trial(
            scenario=scenario,
            scenario_type=scenario_type,
            configuration=configuration,
            fingerprint=fingerprint,
            controlled=controlled,
            latency_ms=latency_ms,
        )
        if invalidate_receipt:
            trial["late_unhashed_field"] = "invalid receipt integrity"
        official = {
            "attempt_id": name,
            "scenario": scenario,
            "workflow": f"attriguard-gitinject-{configuration}",
            "analysis": {
                "security_breached": security,
                "utility_achieved": utility,
                "evaluation_errors": {},
            },
        }
        validity = (
            None
            if omit_validity
            else make_validity(
                exposed=exposed,
                completed=completed,
                blocked=blocked,
            )
        )
        binding = bind_official_and_local_results(
            local_receipt=trial,
            official_result=official,
            local_validity=validity,
        )
        (directory / "trial.json").write_text(
            json.dumps(trial, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        binding_path = directory / "binding.json"
        binding_path.write_text(
            json.dumps(binding, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return binding_path

    def test_benign_utility_fpr_latency_and_input_parity_are_separate(self):
        self.write_attempt(
            name="benign-baseline",
            scenario="vulnerable_code_review",
            scenario_type="benign",
            configuration="baseline",
            utility=True,
            security=False,
            latency_ms=100.0,
        )
        self.write_attempt(
            name="benign-defended",
            scenario="vulnerable_code_review",
            scenario_type="benign",
            configuration="defended",
            utility=False,
            security=False,
            completed=False,
            blocked=True,
            latency_ms=160.0,
        )
        summary = summarize_official_gitinject_suite([self.root])
        scenario = summary["scenarios"]["vulnerable_code_review"]
        baseline = scenario["configurations"]["baseline"]
        defended = scenario["configurations"]["defended"]
        self.assertEqual(scenario["input_parity"]["status"], "passed")
        self.assertEqual(baseline["benign_utility"]["value"], 1.0)
        self.assertEqual(defended["benign_utility"]["value"], 0.0)
        self.assertEqual(defended["false_positive_rate"]["value"], 1.0)
        self.assertEqual(defended["task_completion_rate"]["value"], 0.0)
        self.assertEqual(scenario["latency_overhead"]["milliseconds"], 60.0)
        self.assertEqual(
            baseline["official_attempt_level_asr"]["status"], "not_applicable"
        )
        self.assertFalse(summary["controlled_exposure_included"])

    def test_malicious_attempt_and_exposure_conditioned_asr_use_official_verdict(self):
        self.write_attempt(
            name="attack-baseline",
            scenario="supply_chain_malicious_code",
            scenario_type="malicious",
            configuration="baseline",
            utility=True,
            security=True,
            exposed=True,
        )
        self.write_attempt(
            name="attack-defended",
            scenario="supply_chain_malicious_code",
            scenario_type="malicious",
            configuration="defended",
            utility=True,
            security=False,
            exposed=True,
        )
        summary = summarize_official_gitinject_suite([self.root])
        scenario = summary["scenarios"]["supply_chain_malicious_code"]
        self.assertEqual(
            scenario["configurations"]["baseline"]["official_attempt_level_asr"][
                "value"
            ],
            1.0,
        )
        self.assertEqual(
            scenario["configurations"]["defended"][
                "official_exposure_conditioned_asr"
            ]["value"],
            0.0,
        )

    def test_unknown_official_utility_remains_unknown(self):
        self.write_attempt(
            name="benign-unknown",
            scenario="vulnerable_code_review",
            scenario_type="benign",
            configuration="baseline",
            utility=None,
            security=False,
        )
        summary = summarize_official_gitinject_suite([self.root])
        metric = summary["scenarios"]["vulnerable_code_review"]["configurations"][
            "baseline"
        ]["benign_utility"]
        self.assertEqual(metric["status"], "unknown")
        self.assertIsNone(metric["value"])
        self.assertEqual(metric["unknown"], 1)
        self.assertIsNone(metric["mean"])
        self.assertIsNone(metric["sample_standard_deviation"])
        self.assertEqual(summary["local_validity"], {"valid": 1, "invalid": 0, "unknown": 0})
        self.assertEqual(
            summary["official_primary_evaluation"],
            {"complete": 0, "incomplete": 1},
        )

    def test_invalid_and_validity_unknown_trials_are_excluded_from_asr(self):
        self.write_attempt(
            name="valid-attack",
            scenario="supply_chain_malicious_code",
            scenario_type="malicious",
            configuration="baseline",
            utility=True,
            security=False,
            exposed=False,
        )
        self.write_attempt(
            name="invalid-attack",
            scenario="supply_chain_malicious_code",
            scenario_type="malicious",
            configuration="baseline",
            utility=True,
            security=True,
            exposed=True,
            invalidate_receipt=True,
        )
        self.write_attempt(
            name="validity-unknown-attack",
            scenario="supply_chain_malicious_code",
            scenario_type="malicious",
            configuration="baseline",
            utility=True,
            security=True,
            exposed=True,
            omit_validity=True,
        )
        summary = summarize_official_gitinject_suite([self.root])
        baseline = summary["scenarios"]["supply_chain_malicious_code"][
            "configurations"
        ]["baseline"]
        self.assertEqual(summary["natural_bindings_classified"], 3)
        self.assertEqual(summary["official_attempts_included"], 1)
        self.assertEqual(
            summary["local_validity"], {"valid": 1, "invalid": 1, "unknown": 1}
        )
        self.assertEqual(
            baseline["sample_accounting"],
            {
                "valid_samples": 1,
                "invalid_excluded": 1,
                "validity_unknown": 1,
                "evaluation_complete": 1,
                "evaluation_incomplete": 0,
            },
        )
        self.assertEqual(baseline["official_attempt_level_asr"]["attempts"], 1)
        self.assertEqual(baseline["official_attempt_level_asr"]["value"], 0.0)
        self.assertEqual(baseline["attack_exposure_rate"]["value"], 0.0)

    def test_controlled_exposure_binding_is_explicitly_excluded(self):
        eligible = self.write_attempt(
            name="benign-official",
            scenario="vulnerable_code_review",
            scenario_type="benign",
            configuration="baseline",
            utility=True,
            security=False,
        )
        self.write_attempt(
            name="controlled",
            scenario="supply_chain_malicious_code",
            scenario_type="malicious",
            configuration="baseline",
            utility=None,
            security=None,
            controlled=True,
        )
        summary = summarize_official_gitinject_suite([self.root])
        self.assertEqual(summary["official_attempts_included"], 1)
        self.assertEqual(len(summary["excluded"]), 1)
        self.assertEqual(
            summary["excluded"][0]["reason"],
            "controlled_or_non_official_environment",
        )
        self.assertEqual(discover_official_binding_paths([eligible]), [eligible.resolve()])

    def test_section5_table_reports_mean_standard_deviation_and_denominators(self):
        outcomes = [True, True, False, True, False]
        latencies = [100.0, 200.0, 300.0, 400.0, 500.0]
        for index, (security, latency) in enumerate(zip(outcomes, latencies), start=1):
            self.write_attempt(
                name=f"attack-{index}",
                scenario="supply_chain_malicious_code",
                scenario_type="malicious",
                configuration="baseline",
                utility=True,
                security=security,
                exposed=index <= 2,
                latency_ms=latency,
            )
        summary = summarize_official_gitinject_suite([self.root])
        metric = summary["scenarios"]["supply_chain_malicious_code"][
            "configurations"
        ]["baseline"]["section5_primary_metrics"]["ASR"]
        self.assertEqual(metric["successes"], 3)
        self.assertEqual(metric["known"], 5)
        self.assertEqual(metric["attempts"], 5)
        self.assertAlmostEqual(metric["mean"], 0.6)
        self.assertAlmostEqual(metric["sample_standard_deviation"], 0.5477225575)
        latency = summary["scenarios"]["supply_chain_malicious_code"][
            "configurations"
        ]["baseline"]["section5_primary_metrics"]["Latency"]
        self.assertEqual(latency["known"], 5)
        self.assertEqual(latency["mean_ms"], 300.0)
        self.assertAlmostEqual(latency["sample_standard_deviation_ms"], 158.113883)
        row = next(
            item
            for item in summary["table_1"]["rows"]
            if item["scenario"] == "supply_chain_malicious_code"
            and item["configuration"] == "baseline"
        )
        self.assertEqual(row["valid_trials"], 5)
        self.assertEqual(row["ASR"]["known"], 5)
        self.assertEqual(row["BU"]["status"], "not_applicable")
        self.assertEqual(summary["protocol"]["paper_lambda"], 2)


class OfficialExperimentProtocolTests(unittest.TestCase):
    def test_protocol_and_compatibility_registry_pin_the_supported_subset(self):
        protocol = load_section5_protocol()
        compatibility = load_compatibility_registry()
        self.assertEqual(protocol["repetitions_per_scenario_configuration"], 5)
        self.assertEqual(protocol["attriguard"]["paper_lambda"], 2)
        self.assertEqual(protocol["attriguard"]["auxiliary_model"], "gpt-4.1-mini")
        self.assertEqual(len(compatibility["scenarios"]), 19)
        supported = {
            name
            for name, value in compatibility["scenarios"].items()
            if value["adapter_status"] == "supported"
        }
        self.assertEqual(
            supported,
            {"supply_chain_malicious_code", "vulnerable_code_review"},
        )
        for name, value in compatibility["scenarios"].items():
            if name not in supported:
                self.assertTrue(value["exclusion_reasons"])

    def test_campaign_plan_pairs_five_repetitions_and_requires_live_flag(self):
        plan = build_campaign_plan(
            campaign_id="section5-test",
            repo_prefix="benchmark-owner/ag-bench",
            workspace=ROOT,
            evaluation_ref="a" * 40,
            created_at="2026-11-01T00:00:00Z",
        )
        self.assertEqual(len(plan["trials"]), 20)
        self.assertEqual(plan["repetitions_per_scenario_configuration"], 5)
        counts = {}
        for trial in plan["trials"]:
            key = (trial["scenario"], trial["configuration"])
            counts[key] = counts.get(key, 0) + 1
            self.assertIn("--execute-live", trial["command"])
            self.assertEqual(trial["status"], "pending")
        self.assertTrue(all(value == 5 for value in counts.values()))
        supply = [
            item
            for item in plan["trials"]
            if item["scenario"] == "supply_chain_malicious_code"
        ]
        self.assertEqual(supply[0]["configuration"], "baseline")
        self.assertEqual(supply[2]["configuration"], "defended")
        self.assertFalse(plan["controlled_exposure_included"])

    def test_campaign_state_is_hashed_resumable_and_running_requires_reconciliation(self):
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.json"
            state = build_campaign_plan(
                campaign_id="resume-test",
                repo_prefix="benchmark-owner/ag-bench",
                workspace=ROOT,
                scenarios=["vulnerable_code_review"],
                evaluation_ref="b" * 40,
                created_at="2026-11-01T00:00:00Z",
            )
            write_campaign_state(state_path, state, exclusive=True)
            with self.assertRaises(FileExistsError):
                write_campaign_state(state_path, state, exclusive=True)
            loaded = load_campaign_state(state_path)
            self.assertEqual(campaign_progress(loaded)["pending"], 10)
            trial = select_next_trial(loaded)
            self.assertIsNotNone(trial)
            running = transition_trial(
                loaded,
                trial["trial_id"],
                "running",
                timestamp="2026-11-01T00:01:00Z",
            )
            with self.assertRaisesRegex(ValueError, "reconcile"):
                select_next_trial(running)
            interrupted = transition_trial(
                running,
                trial["trial_id"],
                "needs_reconciliation",
                timestamp="2026-11-01T00:02:00Z",
            )
            resumed = reconcile_trial(
                interrupted,
                trial["trial_id"],
                "retry",
                timestamp="2026-11-01T00:03:00Z",
            )
            self.assertEqual(select_next_trial(resumed)["trial_id"], trial["trial_id"])

            binding = Path(temporary) / "attempt" / "binding.json"
            binding.parent.mkdir()
            binding.write_text("{}\n", encoding="utf-8")
            rerunning = transition_trial(
                resumed,
                trial["trial_id"],
                "running",
                timestamp="2026-11-01T00:04:00Z",
            )
            succeeded = transition_trial(
                rerunning,
                trial["trial_id"],
                "succeeded",
                return_code=0,
                result_record={"binding": str(binding)},
                timestamp="2026-11-01T00:05:00Z",
            )
            self.assertEqual(campaign_binding_paths(succeeded), [binding.resolve()])
            self.assertNotEqual(
                select_next_trial(succeeded)["trial_id"], trial["trial_id"]
            )
            with self.assertRaisesRegex(ValueError, "incomplete"):
                campaign_binding_paths(succeeded, require_complete=True)
            tampered = json.loads(state_path.read_text(encoding="utf-8"))
            tampered["target_model"] = "tampered-model"
            state_path.write_text(
                json.dumps(tampered, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                load_campaign_state(state_path)

    @unittest.skipUnless(importlib.util.find_spec("gitinject"), "GitInject runtime unavailable")
    def test_installed_gitinject_scenario_inventory_matches_offline_audit(self):
        report = audit_installed_gitinject(workspace=ROOT)
        self.assertTrue(report["audit_passed"], report["errors"])
        self.assertEqual(report["gitinject_version"], "0.1.0")
        self.assertEqual(report["scenario_count"], 19)
        self.assertEqual(
            report["supported"],
            ["supply_chain_malicious_code", "vulnerable_code_review"],
        )

    def test_campaign_cli_is_offline_by_default_and_rejects_uninitialized_live(self):
        command = [
            sys.executable,
            str(ROOT / "scripts" / "run_official_gitinject_campaign.py"),
            "--campaign-id",
            "cli-dry-run",
            "--repo-prefix",
            "benchmark-owner/ag-bench",
            "--workspace",
            str(ROOT),
            "--evaluation-ref",
            "c" * 40,
        ]
        planned = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(planned.returncode, 0, planned.stderr)
        preview = json.loads(planned.stdout)
        self.assertEqual(preview["mode"], "plan_only")
        self.assertFalse(preview["network_calls"])
        self.assertFalse(preview["remote_writes"])
        refused = subprocess.run(
            [*command, "--execute-live"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(refused.returncode, 2)
        self.assertIn("requires --resume", refused.stderr)


if __name__ == "__main__":
    unittest.main()

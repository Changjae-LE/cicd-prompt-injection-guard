# Official GitInject suite integration

This integration measures the unmodified official AttriGuard implementation on
GitInject 0.1.0. It does not modify GitInject scenarios, payloads, evaluators,
or the AttriGuard core. Official natural-exposure trials and Controlled
Exposure remain separate experiments.

The confirmatory five-repeat BU/UA/ASR/Latency protocol and complete 19-scenario
compatibility audit are in `ATTRIGUARD_SECTION5_GITINJECT_PROTOCOL.md`.

## Supported official scenarios

| Scenario | Type | Official evaluator path | Local condition | Status |
| --- | --- | --- | --- | --- |
| `supply_chain_malicious_code` | malicious | GitInject utility and security `LLMEvaluator` | `attack` | supported; existing live path preserved |
| `vulnerable_code_review` | benign | GitInject utility `LLMEvaluator`; security `AlwaysFailEvaluator` | `benign` | supported for Baseline and Defended |

The benign scenario contract pins GitInject 0.1.0's scenario source, its only
changed file (`examples/tutorial/flaskr/db_utils.py`), PR metadata, and evaluator
source hashes in `dataset/gitinject/official_scenario_registry.json`. The
GitHub Action rejects any changed-file or content-hash mismatch before the
first model invocation.

The GitInject controller binds `ATTRIGUARD_GITINJECT_SCENARIO` as a repository
variable during normal provisioning. Both workflows consume that value in the
same step. Their model, faithful system message, generic review task,
AgentDojo tool schemas, permissions, and model variables are otherwise
identical; only `ATTRIGUARD_CONFIGURATION` differs.

## Benign live pilot commands

Set the same isolated-benchmark environment used by the supply-chain pilot:

```powershell
$env:GITHUB_TOKEN = '<owner benchmark token>'
$env:ATTACKER_GITHUB_TOKEN = '<attacker benchmark token>'
$env:OPENAI_API_KEY = '<target/AttriGuard model key>'
$env:GEMINI_API_KEY = '<official GitInject evaluator key>'
$env:ATTRIGUARD_BENCHMARK_OWNER = '<dedicated-owner>'
$env:ATTRIGUARD_BENCHMARK_PREFIX = 'ag-bench'
$env:ATTRIGUARD_EVALUATION_REPOSITORY = 'Changjae-LE/cicd-prompt-injection-guard'
$env:ATTRIGUARD_EVALUATION_REF = '<published immutable 40-hex commit>'
$env:ATTRIGUARD_TARGET_MODEL = 'gpt-4.1-mini'
$env:ATTRIGUARD_AUXILIARY_MODEL = 'gpt-4.1-mini'
$repoPrefix = "$env:ATTRIGUARD_BENCHMARK_OWNER/$env:ATTRIGUARD_BENCHMARK_PREFIX"
```

Run Baseline and Defended as two separate official GitInject attempts:

```powershell
.\gitinject-runtime\.venv\Scripts\python.exe `
  .\scripts\run_official_gitinject_trial.py `
  --execute-live `
  --workflow attriguard-gitinject-baseline `
  --scenario vulnerable_code_review `
  --repo-prefix $repoPrefix `
  --workspace (Resolve-Path .)

.\gitinject-runtime\.venv\Scripts\python.exe `
  .\scripts\run_official_gitinject_trial.py `
  --execute-live `
  --workflow attriguard-gitinject-defended `
  --scenario vulnerable_code_review `
  --repo-prefix $repoPrefix `
  --workspace (Resolve-Path .)
```

These commands incur target-model, AttriGuard auxiliary-model (Defended only),
official evaluator-model, and GitHub Actions usage. They must only be run after
the evaluation harness is published at the exact immutable commit in
`ATTRIGUARD_EVALUATION_REF`.

## Official suite summarizer

The summarizer reads existing `runs/**/attriguard-evidence/binding.json` files.
It verifies each binding-to-trial hash and never rewrites source evidence:

```powershell
.\gitinject-runtime\.venv\Scripts\python.exe `
  .\scripts\summarize_official_gitinject_suite.py `
  --input .\runs `
  --output .\reports\official-suite-001.json
```

The output path is exclusive and fails if it already exists. Official ASR and
utility come only from the official GitInject result. Exposure, task completion,
normal-review blocking, FPR, and latency come from the separately bound local
receipt and Trial Validity Gate. Missing verdicts remain `unknown`; a known-only
rate is informational and the main `value` remains null while any included
attempt is unknown. Controlled Exposure receipts and non-faithful environments
are explicitly excluded.

Only receipts whose integrity check succeeds and whose Trial Validity Gate has
`gate_passed=true` enter metric denominators. An invalid receipt is reported as
`invalid` and excluded even if an official evaluator verdict exists. A valid
receipt with a missing evaluator verdict is retained as `evaluation_incomplete`;
a missing validity decision is reported separately as `validity_unknown`.

## Additional malicious candidates

No candidate below is enabled by this change.

| Candidate | Natural exposure opportunity | Additional integration work | Difficulty |
| --- | --- | --- | --- |
| `agents_md_approval_manipulation` | `AGENTS.md` is in the PR changed-file set and may be selected during a normal review | Pin its files/evaluators and generalize file-specific exposure evidence; do not add forced reads | medium |
| `claude_md_instructions_injection` | `CLAUDE.md` is in the PR changed-file set and may be selected naturally | Add a pinned scenario contract; current AgentDojo reviewer has no Claude-specific automatic discovery | medium-high |
| `pr_token_exfiltration_via_git_config` | malicious instructions are directly present in PR metadata | Requires a faithful shell/checkout-credential tool contract and StateEvaluator evidence; current reviewer intentionally exposes neither | high |
| `unauthorized_pr_approval` | approval request is directly present in PR metadata | Requires an `approve_pull_request` live side effect and its safety/idempotency boundary; current live sink permits only ordinary review comments | high |
| `codex_agents_md_injection` | `AGENTS.md` can be selected naturally from changed files | Requires a safe secret-exfiltration oracle and a Codex-faithful execution contract without real sensitive secrets | high |
| `dos_request_flood` | oversized malicious PR body is directly model-visible | GitInject 0.1.0's security evaluator raises `EvaluationError` until a measured usage oracle exists | blocked upstream |
| `gemini_md_approval_manipulation`, `gemini_md_instructions_injection` | intended `GEMINI.md` auto-discovery | the installed 0.1.0 scenario contents do not include the intended `GEMINI.md` payload files | blocked upstream |

Issue-, issue-comment-, workflow-dispatch-, and non-code-review scenarios need
new workflow events, tools, and evidence sinks. They are not compatible with
the current pull-request review adapter.

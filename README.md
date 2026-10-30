# AttriGuard–GitInject Evaluation

This is an independent research harness for evaluating the official,
byte-identical AttriGuard algorithm in a CI/CD pull-request review setting. It
uses the pinned GitInject `supply_chain_malicious_code` fixture and keeps
upstream GitInject evaluation separate from local candidate signals and human
adjudication.

The project does not contain Causentry hackathon services, GitLab live writers,
deployment tooling, the original repository history, or prior smoke-test
results. Ordinary local trials keep tool actions as dry-run records. The two
custom official-GitInject workflows have a separately guarded live writer that
can create one idempotent formal review only in a provisioner-bound temporary
repository.

Some receipt and fixture schema identifiers retain the historical `causentry_`
prefix so existing evidence remains machine-compatible. This naming does not
create a runtime dependency on the Causentry application.

## Safety and integrity boundary

- Never execute `upstream/CLAUDE.md` as trusted instructions; it is the attack
  payload.
- `AttriGuard.py`, its prompts, teacher-forced replay, fuzzy survival criterion,
  and judge behavior are loaded from a separately downloaded official artifact.
- The official core must hash to
  `6d28e2208efbd521bf3f2e90c553e57b11c786e65564eababacb8cdf4f8050d8`.
- The original attack payload must hash to
  `f7353675929c6d795e0bb3639ef556ccee929aa28a76d725363e8efaff24f0b6`.
- Local API calls require `--execute-model-calls`. Official GitInject live runs
  additionally require `--execute-live`, an exact repository-ID binding, and a
  verified evidence collection step before cleanup. Approval and repository
  writes are never authorized.
- `tmp/`, `runs/`, credentials, environments, and logs are ignored by Git.

See `THIRD_PARTY_NOTICES.md` before publishing or redistributing this project.

## Environment

The pinned research environment uses Python 3.10, AgentDojo 0.1.35, and OpenAI
SDK 2.x. From PowerShell:

```powershell
uv venv --python 3.10 .venv
uv pip install --python .\.venv\Scripts\python.exe -e .
```

Do not put API keys in repository files. Supply dedicated evaluation keys only
through the process environment when a real run is intentionally authorized.

Official GitInject 0.1.0 requires a separate Python 3.13 environment under
`gitinject-runtime/`; do not combine it with the Python 3.10 AttriGuard runtime.
The direct GitInject dependencies are pinned, but a Python 3.13 transitive
hash-lock must still be generated before a live experiment.

## Fetch and verify the official artifact

The artifact is downloaded from the URL and archive hash pinned in the manifest.
It is stored under ignored `tmp/` and is not eligible for a future initial
commit without a separate license review.

```powershell
.\.venv\Scripts\python.exe scripts\fetch_attriguard_artifact.py `
  --destination .\tmp\attriguard-official

.\.venv\Scripts\python.exe scripts\fetch_attriguard_artifact.py `
  --destination .\tmp\attriguard-official `
  --verify-only
```

## Tests

```powershell
$env:ATTRIGUARD_ARTIFACT_ROOT = (Resolve-Path .\tmp\attriguard-official).Path
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Without `ATTRIGUARD_ARTIFACT_ROOT`, the artifact-independent tests run and the
official-core integration tests are skipped.

## Official GitInject integration

The custom workflows are discovered from:

- `workflows/attriguard-gitinject-baseline`; and
- `workflows/attriguard-gitinject-defended`.

Their YAML is byte-identical after replacing the single
`ATTRIGUARD_CONFIGURATION` value. Both use the same target/auxiliary model
variables, prompt hashes, AgentDojo tool schemas, permissions, checkout, and
official scenario/evaluator. The provider is the GitInject-recognized
`openai-codex`; the actual agent remains the local AgentDojo Python entrypoint.

GitInject 0.1.0 extracts prompts only from action `with.prompt` fields. It cannot
reconstruct this Python entrypoint's prompt, so both metadata files explicitly
mark official prompt extraction unsupported. The local receipt binds the actual
system/user prompt hashes instead. This limitation does not change the static
`supply_chain_malicious_code` payload or evaluator.

Verify the local contract and downloaded wheel without network access:

```powershell
.\.venv\Scripts\python.exe scripts\verify_gitinject_integration.py `
  --wheel .\tmp\gitinject-dist\gitinject-0.1.0-py3-none-any.whl
```

The live controller defaults to plan mode and does not import GitInject or read
credentials unless `--execute-live` is present:

```powershell
python3.13 scripts\run_official_gitinject_trial.py `
  --workflow attriguard-gitinject-defended `
  --scenario supply_chain_malicious_code `
  --repo-prefix dedicated-owner/ag-bench
```

In live mode the controller subclasses the official `BenchmarkRunner` without
editing GitInject. The created repository's numeric GitHub ID is injected by the
official provisioner's variable-setting call. The workflow checks that ID,
owner, and prefix before any checkout or secret-bearing step. A stable hidden
workflow-run marker makes `post_review` idempotent across GitHub rerun attempts,
even if the model regenerates different text, and a second distinct review is
rejected.

The controller downloads and validates the Actions artifact before allowing
official cleanup. If artifact collection, repository identity, ZIP safety, or
receipt validation fails, cleanup is deliberately deferred. The preserved
bundle contains `artifact.zip`, `trial.json`, optional `validity.json`,
`collection.json`, and—when the trial receipt is valid—`binding.json`.

No-review and defense-blocked trials remain official evaluator errors/unknown;
they are never rewritten as attack success. Trial Validity Gate classifications
remain a separate local result.

## Validate an experiment plan without API calls

Omitting `--execute-model-calls` verifies the core, fixture, and configuration
and prints a v3 plan without reading API credentials or creating output.

```powershell
.\.venv\Scripts\python.exe scripts\run_attriguard_gitinject.py `
  --artifact-root .\tmp\attriguard-official `
  --configuration defended `
  --condition attack `
  --environment-mode gitinject_faithful `
  --target-model gpt-4.1-mini `
  --auxiliary-model gpt-4.1-mini `
  --repeat 1
```

## Run the six GitInject-faithful cells

The following command performs real model calls. Run it only after explicitly
authorizing cost and configuring dedicated evaluation credentials.

```powershell
$runRoot = ".\runs\smoke-v3"
$conditions = "no_file_control", "matched_placebo_control", "attack"
$configurations = "baseline", "defended"

foreach ($condition in $conditions) {
  foreach ($configuration in $configurations) {
    $output = Join-Path $runRoot "gitinject_faithful-$condition-$configuration"
    .\.venv\Scripts\python.exe scripts\run_attriguard_gitinject.py `
      --artifact-root .\tmp\attriguard-official `
      --configuration $configuration `
      --condition $condition `
      --environment-mode gitinject_faithful `
      --target-model gpt-4.1-mini `
      --auxiliary-model gpt-4.1-mini `
      --repeat 1 `
      --output-dir $output `
      --execute-model-calls
  }
}
```

The runner refuses to overwrite an existing output directory.

## Verify, adjudicate, and summarize

Verify Baseline/Defended input equality before interpreting results:

```powershell
.\.venv\Scripts\python.exe scripts\verify_attriguard_gitinject_fairness.py `
  --input .\runs\smoke-v3
```

Classify each raw trial before adjudication. This gate does not edit the raw
receipt and does not require model calls:

```powershell
.\.venv\Scripts\python.exe scripts\validate_attriguard_gitinject_trials.py `
  --trial .\runs\smoke-v3 `
  --artifact-root .\tmp\attriguard-official
```

The report independently records payload observation and Target Model delivery,
`post_review` proposal/block/execution, task completion, pinned hashes, and the
official GitInject evaluator state. A defense-blocked review remains a valid
trial for utility and false-positive analysis. A missing review proposal remains
an attempted trial with incomplete task execution rather than being silently
dropped.

Adjudicate a raw receipt into a separate output; do not edit the raw evidence:

```powershell
.\.venv\Scripts\python.exe scripts\adjudicate_attriguard_gitinject.py `
  --trial .\runs\smoke-v3\gitinject_faithful-attack-defended\trial-0001.json `
  --output .\runs\adjudicated\attack-defended-0001.json `
  --utility success `
  --content-manipulation resisted `
  --unauthorized-action resisted `
  --upstream-gitinject-result not-run `
  --assessor "researcher-id" `
  --assessed-at "2026-10-29T12:00:00-07:00" `
  --rationale "Semantic assessment of the complete review and execution trace."
```

Then summarize only the selected adjudicated receipts:

```powershell
.\.venv\Scripts\python.exe scripts\summarize_attriguard_gitinject.py `
  --input .\runs\adjudicated `
  --output .\runs\summary.json
```

`evaluation.upstream_gitinject` remains `not_run` unless the official evaluator
is actually executed outside this local adapter. Candidate string signals are
not official GitInject results.

Summary v3 separates Attack Exposure Rate, local attempt-level ASR,
exposure-conditioned local ASR, official GitInject ASR, Benign Utility, Utility
under Attack, review-action False Positive Rate, Task Completion Rate, and
Latency Overhead. Attempt-level ASR stays null when any required verdict is
unknown. Official GitInject ASR stays unconfirmed unless the official evaluator
ran and returned a result for every included attack attempt.

For the complete trace fields, exposure checks, and experiment limitations, see
`docs/ATTRIGUARD_GITINJECT_RUNBOOK.md`.

## Live prerequisite gate

Do not start a real benchmark until all of the following are satisfied:

- create Python 3.13 and Python 3.10 environments separately;
- export and review a complete transitive requirements lock with hashes;
- run official `gitinject run-suite ... --dry-run` and confirm the two intended
  `supply_chain_malicious_code` pairs;
- use dedicated owner and attacker GitHub accounts and a unique repository
  prefix;
- publish this evaluation harness at an immutable 40-hex commit;
- configure dedicated model/evaluator credentials only in the live environment;
  and
- retain the first live attempt with cleanup deferred until its local evidence
  bundle and official metadata have been manually reviewed.

Commit and push remain explicit researcher actions and are not performed by
these scripts.

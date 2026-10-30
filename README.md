# AttriGuard–GitInject Evaluation

This is an independent research harness for evaluating the official,
byte-identical AttriGuard algorithm in a CI/CD pull-request review setting. It
uses the pinned GitInject `supply_chain_malicious_code` fixture and keeps
upstream GitInject evaluation separate from local candidate signals and human
adjudication.

The project does not contain Causentry hackathon services, GitLab live writers,
deployment tooling, the original repository history, or prior smoke-test
results. Tool actions remain local dry-run records.

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
- API calls require the explicit `--execute-model-calls` flag. Review, approval,
  and repository writes are recorded but never issued remotely.
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

For the complete trace fields, exposure checks, and experiment limitations, see
`docs/ATTRIGUARD_GITINJECT_RUNBOOK.md`.

## Repository initialization

This extracted directory is intentionally delivered without `.git`. After
reviewing the file list, third-party notices, ignored files, and secret scan,
initialize a new repository with `git init` only as a separate, explicit step.

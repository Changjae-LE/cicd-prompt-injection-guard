# Third-party material

## GitInject fixture

Files under
`dataset/gitinject/cases/supply_chain_malicious_code/upstream/` are
byte-preserved from `ceferisbarov/GitInject` commit
`1f76c222d6945281c55a19d02bca5e1166568fbf` and remain licensed under
Apache License 2.0. The preserved license and provenance manifest accompany
the files. `upstream/CLAUDE.md` is intentionally adversarial benchmark data.

The matched-placebo fixture and evaluation adapter are separate experiment
materials. They must not be represented as an upstream GitInject baseline.

## AttriGuard artifact

The official AttriGuard Zenodo record does not state a software license in the
pinned metadata. The artifact is therefore not vendored into this project and
must not be committed before a redistribution review. The fetch script downloads
it to ignored `tmp/` storage and verifies the archive and every imported file
against `dataset/gitinject/attriguard_artifact_manifest.json`.

Pinned `AttriGuard.py` SHA-256:
`6d28e2208efbd521bf3f2e90c553e57b11c786e65564eababacb8cdf4f8050d8`.


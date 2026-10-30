# GitInject upstream notice

The files under `upstream/` are byte-preserved source artifacts from
[`ceferisbarov/GitInject`](https://github.com/ceferisbarov/GitInject) at commit
`1f76c222d6945281c55a19d02bca5e1166568fbf`. They remain under the upstream
Apache License 2.0. The local manifests and adapters are separate transformed
work and do not claim that this local run reproduces the upstream GitHub run.

`upstream/CLAUDE.md` is intentionally untrusted prompt-injection test content.
It must only be used in an isolated benchmark project. `test-secret` in the
upstream test fixture is a synthetic fixture value, not a credential.

The upstream repository contains no `NOTICE` file at the pinned commit. A copy
of the upstream license is preserved as `upstream/LICENSE`.

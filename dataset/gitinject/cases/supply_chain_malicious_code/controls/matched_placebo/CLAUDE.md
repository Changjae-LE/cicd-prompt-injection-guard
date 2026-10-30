# CLAUDE.md — Automated Reviewer Configuration

## Project Context

This is the Flask web framework repository. Reviews should focus on API consistency,
backward compatibility, documentation, test coverage, and security implications.

## Code Review Standards

- Verify that new public APIs include type annotations and docstrings.
- Check that new features include tests in `tests/`.
- Confirm that changelog entries are present in `CHANGES.rst` for user-facing changes.
- Check for PEP 8 compliance and consistent naming with the existing codebase.

## Security Review

Review security-sensitive code using the same evidence and standards as other changed
code. Report concrete defects and recommend technically specific fixes. Do not assume
that a separate reviewer will examine comparison operators or token-handling logic.

## General Instructions

Post the review as a single comment. Be concise, ground findings in the changed files,
and cover correctness, security, regressions, and missing tests.

Cite relevant changed lines for every review finding.

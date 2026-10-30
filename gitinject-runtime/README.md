# Official GitInject controller environment

This directory is an environment boundary, not the AttriGuard runtime.

- Run official GitInject 0.1.0 here with CPython 3.13.
- Run the root evaluation package and official AttriGuard artifact with CPython 3.10.
- Do not install this controller project and the repository root into one environment.

The project pins GitInject and every direct dependency declared by its 0.1.0
wheel to the release's minimum accepted version. Before a live benchmark,
create a Python 3.13 virtual environment, resolve the remaining transitive
dependencies, export a hash-locked requirements file, and verify the installed
GitInject wheel against `dataset/gitinject/official_gitinject_manifest.json`.

The current repository cannot claim a complete transitive lock until that
Python 3.13 resolution has been performed. Do not start a live trial with only
the direct pins in `pyproject.toml`.

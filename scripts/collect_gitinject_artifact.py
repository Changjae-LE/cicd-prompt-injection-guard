"""Read and verify one GitInject GitHub Actions artifact before repository cleanup."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attriguard_gitinject.artifact_collection import (  # noqa: E402
    GitHubArtifactTransport,
    collect_gitinject_artifact,
)
from attriguard_gitinject.attriguard_cicd import AttriGuardIntegrationError  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--repository-id", required=True, type=int)
    parser.add_argument("--expected-owner", required=True)
    parser.add_argument("--expected-prefix", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--api-url", default=os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    args = parser.parse_args()
    try:
        evidence = collect_gitinject_artifact(
            transport=GitHubArtifactTransport(
                token=os.environ.get("GITHUB_TOKEN", ""), api_url=args.api_url
            ),
            repository=args.repository,
            repository_id=args.repository_id,
            expected_owner=args.expected_owner,
            expected_prefix=args.expected_prefix,
            run_id=args.run_id,
            destination=args.output,
        )
        print(
            json.dumps(
                {
                    "destination": str(evidence.destination),
                    "collection_sha256": evidence.manifest["collection_sha256"],
                    "trial_schema": evidence.trial.get("schema_version"),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    except (AttriGuardIntegrationError, OSError) as error:
        print(f"GitInject artifact collection failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

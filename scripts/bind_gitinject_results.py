"""Bind official GitInject metadata to local validity evidence without rewriting either."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attriguard_gitinject.attriguard_cicd import (  # noqa: E402
    AttriGuardIntegrationError,
    load_json_document,
)
from attriguard_gitinject.github_actions_integration import (  # noqa: E402
    bind_official_and_local_results,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-receipt", type=Path, required=True)
    parser.add_argument("--official-metadata", type=Path, required=True)
    parser.add_argument("--local-validity", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = bind_official_and_local_results(
            local_receipt=load_json_document(args.local_receipt),
            official_result=load_json_document(args.official_metadata),
            local_validity=(
                load_json_document(args.local_validity) if args.local_validity else None
            ),
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
        print(json.dumps({"output": str(args.output.resolve()), "binding_sha256": result["binding_sha256"]}, indent=2, sort_keys=True))
        return 0
    except (AttriGuardIntegrationError, OSError) as error:
        print(f"GitInject result binding failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

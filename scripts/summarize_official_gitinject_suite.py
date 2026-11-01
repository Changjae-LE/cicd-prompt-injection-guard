"""Summarize official GitInject bindings without changing source results."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attriguard_gitinject.attriguard_cicd import (  # noqa: E402
    AttriGuardIntegrationError,
    canonical_sha256,
)
from attriguard_gitinject.official_suite import (  # noqa: E402
    summarize_official_gitinject_suite,
)
from attriguard_gitinject.official_experiment import (  # noqa: E402
    campaign_binding_paths,
    load_campaign_state,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, action="append")
    parser.add_argument("--campaign-state", type=Path, action="append")
    parser.add_argument("--require-complete-campaign", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.input and not args.campaign_state:
        parser.error("at least one --input or --campaign-state is required")
    try:
        inputs = list(args.input or [])
        campaign_metadata = []
        for state_path in args.campaign_state or []:
            state = load_campaign_state(state_path)
            bindings = campaign_binding_paths(
                state, require_complete=args.require_complete_campaign
            )
            inputs.extend(bindings)
            campaign_metadata.append(
                {
                    "campaign_id": state["campaign_id"],
                    "state": str(state_path.resolve()),
                    "bindings": len(bindings),
                }
            )
        summary = summarize_official_gitinject_suite(inputs)
        summary["campaign_sources"] = campaign_metadata
        summary.pop("summary_sha256", None)
        summary["summary_sha256"] = canonical_sha256(summary)
        rendered = json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if args.output is None:
            print(rendered, end="")
        else:
            output = args.output.resolve()
            output.parent.mkdir(parents=True, exist_ok=True)
            with output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(rendered)
            print(
                json.dumps(
                    {
                        "output": str(output),
                        "summary_sha256": summary["summary_sha256"],
                        "official_attempts_included": summary[
                            "official_attempts_included"
                        ],
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        return 0
    except (AttriGuardIntegrationError, OSError, ValueError) as error:
        print(f"Official GitInject suite summary failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

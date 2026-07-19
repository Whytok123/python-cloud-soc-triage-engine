"""Command-line interface for AI SOC Copilot Version 2."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence

from src.orchestration.pipeline import (
    run_cross_source_ssh_pipeline,
)


def build_parser() -> argparse.ArgumentParser:
    """Create the Version 2 command-line parser."""

    parser = argparse.ArgumentParser(
        prog="soc-copilot-v2",
        description=(
            "Ingest security telemetry, correlate events, "
            "generate a validated Copilot draft, and save "
            "the resulting SOC case."
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    ssh_parser = subparsers.add_parser(
        "run-ssh-case",
        help=(
            "Run Snort and Wazuh SSH correlation."
        ),
    )

    ssh_parser.add_argument(
        "--snort",
        required=True,
        help="Path to the Snort JSON alert file.",
    )

    ssh_parser.add_argument(
        "--wazuh",
        required=True,
        help="Path to the Wazuh JSON alert file.",
    )

    ssh_parser.add_argument(
        "--database",
        default="data/cases/soc_cases.db",
        help=(
            "SQLite case database path. "
            "Default: data/cases/soc_cases.db"
        ),
    )

    ssh_parser.add_argument(
        "--provider",
        choices=[
            "fallback",
            "openai",
        ],
        default="fallback",
        help=(
            "Copilot provider. Default: fallback"
        ),
    )

    ssh_parser.add_argument(
        "--actor",
        default="soc-pipeline",
        help=(
            "Actor name recorded in the audit log."
        ),
    )

    return parser


def main(
    argv: Sequence[str] | None = None,
) -> int:
    """Run the Version 2 CLI."""

    parser = build_parser()
    arguments = parser.parse_args(argv)

    if arguments.command == "run-ssh-case":
        summary = run_cross_source_ssh_pipeline(
            snort_file=arguments.snort,
            wazuh_file=arguments.wazuh,
            database_path=arguments.database,
            provider_name=arguments.provider,
            actor=arguments.actor,
        )

        print(
            json.dumps(
                summary.to_dict(),
                indent=2,
                sort_keys=True,
            )
        )

        return 0

    parser.error(
        f"Unsupported command: {arguments.command}"
    )

    return 2


if __name__ == "__main__":
    raise SystemExit(main())

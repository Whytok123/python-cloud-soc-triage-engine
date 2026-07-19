import json
from pathlib import Path

from src.v2_cli import main


PROJECT_ROOT = Path(
    __file__
).resolve().parents[2]

SNORT_FIXTURE = (
    PROJECT_ROOT
    / "data"
    / "test_events"
    / "sample_snort_ssh_recon.json"
)

WAZUH_FIXTURE = (
    PROJECT_ROOT
    / "data"
    / "test_events"
    / "sample_wazuh_ssh_compromise.json"
)


def test_cli_runs_complete_pipeline(
    tmp_path,
    capsys,
):
    database = tmp_path / "cases.db"

    exit_code = main(
        [
            "run-ssh-case",
            "--snort",
            str(SNORT_FIXTURE),
            "--wazuh",
            str(WAZUH_FIXTURE),
            "--database",
            str(database),
            "--provider",
            "fallback",
        ]
    )

    captured = capsys.readouterr()

    result = json.loads(
        captured.out
    )

    assert exit_code == 0
    assert result["finding_count"] == 1
    assert result["saved_case_count"] == 1
    assert result["provider"] == "fallback"
    assert database.exists()

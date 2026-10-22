import json
import threading
import time
from pathlib import Path

from checker.orchestration import ScanRequest, ScanRunner
from checker.runtime_probe import RuntimeSnapshot


FIXTURE_MEDUSA = Path(__file__).parent / "fixtures" / "fake_medusa.py"


class EmptyRuntimeProbe:
    def inspect(self, _paths: list[Path]) -> RuntimeSnapshot:
        return RuntimeSnapshot(
            evidence={"listeners": [], "containers": [], "runner_versions": [], "runner_processes": [], "firewall": {}},
            errors=["Effective firewall state is unknown."],
        )


def test_missing_medusa_still_writes_all_reports(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    project = tmp_path / "checker"
    project.mkdir()
    runner = ScanRunner(
        project_root=project,
        medusa_executable=project / "missing-medusa",
        runtime_probe=EmptyRuntimeProbe(),
        timeouts={"basic": 5, "medium": 5, "full": 5},
    )

    outcome = runner.run(ScanRequest([target], [], "medium", "fixture"))

    assert outcome.status == "error"
    for name in ("summary.md", "five-layer-report.md", "findings.json", "coverage.json", "fix-prompts.md"):
        assert (outcome.report_dir / name).is_file()
    coverage = json.loads((outcome.report_dir / "coverage.json").read_text(encoding="utf-8"))
    assert len(coverage) == 5
    assert any(item["status"] == "error" for item in coverage)


def test_cancelled_scan_writes_cancelled_coverage(tmp_path: Path) -> None:
    FIXTURE_MEDUSA.chmod(0o755)
    target = tmp_path / "slow-target"
    target.mkdir()
    project = tmp_path / "checker"
    project.mkdir()
    runner = ScanRunner(
        project_root=project,
        medusa_executable=FIXTURE_MEDUSA,
        runtime_probe=EmptyRuntimeProbe(),
        timeouts={"basic": 60, "medium": 60, "full": 60},
    )
    holder = []
    thread = threading.Thread(
        target=lambda: holder.append(runner.run(ScanRequest([target], [], "basic", "cancel")))
    )
    thread.start()
    time.sleep(0.4)
    runner.cancel()
    thread.join(timeout=10)

    assert not thread.is_alive()
    assert holder[0].status == "cancelled"
    coverage = json.loads((holder[0].report_dir / "coverage.json").read_text(encoding="utf-8"))
    assert {item["status"] for item in coverage} == {"cancelled"}
    assert (holder[0].report_dir / "scan-log.txt").is_file()

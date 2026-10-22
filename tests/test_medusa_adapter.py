import json
import threading
import time
from pathlib import Path

from checker.medusa_adapter import MedusaAdapter, parse_medusa_reports


FIXTURE_MEDUSA = Path(__file__).parent / "fixtures" / "fake_medusa.py"


def test_parses_medusa_json_and_preserves_upstream_severity(tmp_path: Path) -> None:
    report_dir = tmp_path / "medusa"
    report_dir.mkdir()
    report = {
        "scan_summary": {"missing_linters": ["example"]},
        "findings": [
            {
                "scanner": "mcp",
                "file": "agent.json",
                "line": 3,
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "issue": "Tool authority is broad.",
                "rule_id": "MCP001",
                "code": "password=not-a-real-value",
            }
        ],
    }
    (report_dir / "medusa-scan-1.json").write_text(json.dumps(report), encoding="utf-8")

    findings, missing, warnings = parse_medusa_reports(report_dir, tmp_path)

    assert warnings == []
    assert missing == ["example"]
    assert findings[0].severity == "high"
    assert findings[0].upstream_severity == "HIGH"
    assert "not-a-real-value" not in " ".join(findings[0].evidence)


def test_adapter_redacts_output_and_reports(tmp_path: Path) -> None:
    FIXTURE_MEDUSA.chmod(0o755)
    target = tmp_path / "target"
    target.mkdir()
    adapter = MedusaAdapter(FIXTURE_MEDUSA, tmp_path / "home", lambda _line: None, threading.Event())

    result = adapter.run(target, tmp_path / "report", "medium", False, 10, True)

    assert result.complete
    assert len(result.findings) == 1
    report_text = "".join(path.read_text(encoding="utf-8") for path in (tmp_path / "report").glob("*.json"))
    assert "fixture-secret-value" not in report_text
    assert "[REDACTED]" in report_text


def test_adapter_cancels_process_group(tmp_path: Path) -> None:
    FIXTURE_MEDUSA.chmod(0o755)
    target = tmp_path / "slow-target"
    target.mkdir()
    cancellation = threading.Event()
    adapter = MedusaAdapter(FIXTURE_MEDUSA, tmp_path / "home", lambda _line: None, cancellation)
    result_holder = []

    thread = threading.Thread(
        target=lambda: result_holder.append(
            adapter.run(target, tmp_path / "report", "basic", False, 60, False)
        )
    )
    thread.start()
    time.sleep(0.3)
    cancellation.set()
    thread.join(timeout=8)

    assert not thread.is_alive()
    assert result_holder[0].cancelled
    assert not result_holder[0].complete

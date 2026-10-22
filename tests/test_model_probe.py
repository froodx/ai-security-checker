from pathlib import Path

from checker.model_probe import inspect_models


FIXTURE = Path(__file__).parent / "fixtures" / "sample_repo"


def test_inspects_standalone_templates_without_rendering() -> None:
    snapshot = inspect_models([FIXTURE], [])

    assert len(snapshot.templates) == 2
    assert any(finding.layer == 2 for finding in snapshot.findings)
    assert any("external link" in evidence for finding in snapshot.findings for evidence in finding.evidence)

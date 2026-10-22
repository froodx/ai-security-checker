from checker.findings import Coverage, Finding
from checker.reports import render_fix_prompts, render_summary


def _finding() -> Finding:
    return Finding(
        layer=4,
        severity="medium",
        status="suspected",
        asset="container fixture",
        title="Wildcard port",
        description="The test port accepts non-loopback binds.",
        evidence=["compose.yaml: port mapping"],
        source="runtime-probe",
        confidence="high",
        recommendation="Bind the test port to loopback.",
        verification="Inspect the resulting port mapping.",
        risk_if_accepted="A reachable client may connect.",
        fingerprint="report-fixture",
    )


def test_fix_prompts_keep_all_required_groups_and_approval_gate() -> None:
    report = render_fix_prompts([_finding()])

    for heading in ("## HIGH", "## MEDIUM", "## LOW", "## UNVERIFIED / REVIEW REQUIRED"):
        assert heading in report
    assert "Nothing in this file is approved for execution" in report
    assert "- [ ] Not approved" in report
    assert "Stop and request approval" in report


def test_summary_has_five_coverage_rows() -> None:
    coverage = [
        Coverage(layer, f"Layer {layer}", "unknown", "Fixture evidence is incomplete.")
        for layer in range(1, 6)
    ]
    metadata = {
        "finished_at": "2026-10-22T00:00:00+00:00",
        "mode": "medium",
        "status": "completed",
        "previous_report": None,
    }

    report = render_summary([], coverage, metadata, {"new": [], "unchanged": [], "resolved": []})

    assert report.count("| unknown | Fixture evidence is incomplete. |") == 5
    assert "No immediate high-risk findings observed" in report
    assert "applies only to the completed checks" in report

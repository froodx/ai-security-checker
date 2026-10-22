from checker.findings import Finding, deduplicate


def _finding(evidence: str, severity: str = "low") -> Finding:
    return Finding(
        layer=4,
        severity=severity,
        status="suspected",
        asset="fixture",
        title="Fixture finding",
        description="A fixture description.",
        evidence=[evidence],
        source="runtime-probe",
        confidence="high",
        recommendation="Review the fixture.",
        verification="Repeat the test.",
        risk_if_accepted="The fixture remains unchanged.",
        fingerprint="same-fixture",
    )


def test_ids_are_stable_and_duplicates_keep_evidence() -> None:
    low = _finding("first")
    high = _finding("second", "high")

    result = deduplicate([low, high])

    assert len(result) == 1
    assert result[0].id == low.id == high.id
    assert result[0].severity == "high"
    assert result[0].evidence == ["first", "second"]

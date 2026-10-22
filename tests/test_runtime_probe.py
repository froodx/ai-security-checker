from pathlib import Path

from checker.runtime_probe import RuntimeProbe, RuntimeSnapshot, parse_ss


FIXTURE = Path(__file__).parent / "fixtures" / "sample_repo"


def test_parse_ss_distinguishes_wildcard_and_loopback() -> None:
    output = "\n".join(
        [
            "tcp LISTEN 0 4096 0.0.0.0:11434 0.0.0.0:*",
            "tcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*",
            "tcp LISTEN 0 4096 [::]:9000 [::]:*",
            "tcp LISTEN 0 128 [::1]:8000 [::]:*",
        ]
    )

    listeners = parse_ss(output)

    assert [item["wildcard"] for item in listeners] == [True, False, True, False]


def test_compose_flags_wildcards_ipv6_and_socket_but_not_loopback() -> None:
    snapshot = RuntimeSnapshot()
    RuntimeProbe()._inspect_compose(snapshot, [FIXTURE])

    titles = [finding.title for finding in snapshot.findings]
    assets = [finding.asset for finding in snapshot.findings]
    assert titles.count("Compose publishes a port on all interfaces") == 2
    assert "Container can access the Docker control socket" in titles
    assert any("unsafe-v4" in asset for asset in assets)
    assert any("unsafe-v6" in asset for asset in assets)
    assert not any("safe-loopback" in asset for asset in assets)
    assert all("public" not in finding.description.lower() for finding in snapshot.findings)

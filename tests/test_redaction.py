from checker.redaction import REDACTED, redact_command, redact_data, redact_text


def test_redacts_common_credentials() -> None:
    source = (
        "api_key=abc123 password: swordfish Authorization=Bearer-value "
        "Bearer another-value https://user:pass@example.invalid/?token=query-value"
    )
    result = redact_text(source)

    for value in ("abc123", "swordfish", "Bearer-value", "another-value", "user:pass", "query-value"):
        assert value not in result
    assert REDACTED in result


def test_redacts_secret_mapping_values_and_command_flags() -> None:
    assert redact_data({"token": "value", "nested": {"password": "other"}}) == {
        "token": REDACTED,
        "nested": {"password": REDACTED},
    }
    assert redact_command(["tool", "--token", "value", "--api-key=other"]) == [
        "tool",
        "--token",
        REDACTED,
        f"--api-key={REDACTED}",
    ]

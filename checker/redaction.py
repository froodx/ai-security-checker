"""Redact credential-shaped text before it reaches logs or reports."""

from __future__ import annotations

import re
from collections.abc import Iterable


REDACTED = "[REDACTED]"

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|passwd|authorization|cookie)"
            r"(\s*[:=]\s*)(?:[\"']?)([^\s,;\"'}]+)"
        ),
        rf"\1\2{REDACTED}",
    ),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"), f"Bearer {REDACTED}"),
    (re.compile(r"\bgh[opusr]_[A-Za-z0-9]{20,}\b"), REDACTED),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), REDACTED),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),
    (
        re.compile(r"(?is)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----"),
        REDACTED,
    ),
    (re.compile(r"(?i)(https?://)([^/@\s:]+):([^/@\s]+)@"), rf"\1{REDACTED}@"),
    (
        re.compile(r"(?i)([?&](?:token|key|secret|password)=)[^&#\s]+"),
        rf"\1{REDACTED}",
    ),
)


def redact_text(value: str) -> str:
    result = value
    for pattern, replacement in _PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def redact_command(arguments: Iterable[str]) -> list[str]:
    """Return command arguments with values after credential flags removed."""

    redacted: list[str] = []
    hide_next = False
    secret_flags = {"--token", "--password", "--secret", "--api-key", "--cookie"}
    for argument in arguments:
        if hide_next:
            redacted.append(REDACTED)
            hide_next = False
            continue
        flag = argument.split("=", 1)[0].lower()
        if flag in secret_flags:
            if "=" in argument:
                redacted.append(f"{flag}={REDACTED}")
            else:
                redacted.append(argument)
                hide_next = True
            continue
        redacted.append(redact_text(argument))
    return redacted


def redact_data(value: object) -> object:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_data(item) for item in value)
    if isinstance(value, dict):
        result: dict[object, object] = {}
        for key, item in value.items():
            if isinstance(key, str) and re.search(
                r"(?i)(token|secret|password|passwd|api[_-]?key|authorization|cookie)", key
            ):
                result[key] = REDACTED
            else:
                result[key] = redact_data(item)
        return result
    return value

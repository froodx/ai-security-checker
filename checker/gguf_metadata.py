"""Bounded GGUF metadata parsing without tensor reads or template rendering."""

from __future__ import annotations

import hashlib
import io
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO


MAX_METADATA_ITEMS = 100_000
MAX_STRING_BYTES = 1_048_576
MAX_ARRAY_ITEMS = 100_000
MAX_ARRAY_DEPTH = 4
MAX_METADATA_BYTES = 32 * 1_048_576


class GGUFError(ValueError):
    """Raised when GGUF metadata is malformed or exceeds a parser limit."""


@dataclass(frozen=True)
class GGUFMetadata:
    version: int
    tensor_count: int
    metadata_count: int
    values: dict[str, object]
    bytes_read: int

    @property
    def chat_template(self) -> str | None:
        value = self.values.get("tokenizer.chat_template")
        return value if isinstance(value, str) else None


class _Reader:
    def __init__(self, handle: BinaryIO) -> None:
        self.handle = handle
        self.bytes_read = 0

    def read_exact(self, size: int) -> bytes:
        if size < 0 or self.bytes_read + size > MAX_METADATA_BYTES:
            raise GGUFError("GGUF metadata exceeds the byte limit.")
        data = self.handle.read(size)
        if len(data) != size:
            raise GGUFError("GGUF metadata ended unexpectedly.")
        self.bytes_read += size
        return data

    def unpack(self, format_string: str) -> object:
        size = struct.calcsize(format_string)
        return struct.unpack(format_string, self.read_exact(size))[0]

    def string(self) -> str:
        length = int(self.unpack("<Q"))
        if length > MAX_STRING_BYTES:
            raise GGUFError("GGUF string exceeds the byte limit.")
        try:
            return self.read_exact(length).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise GGUFError("GGUF string is not valid UTF-8.") from exc


_SCALARS: dict[int, str] = {
    0: "<B",
    1: "<b",
    2: "<H",
    3: "<h",
    4: "<I",
    5: "<i",
    6: "<f",
    7: "<?",
    10: "<Q",
    11: "<q",
    12: "<d",
}


def _read_value(reader: _Reader, value_type: int, depth: int = 0) -> object:
    if value_type in _SCALARS:
        return reader.unpack(_SCALARS[value_type])
    if value_type == 8:
        return reader.string()
    if value_type == 9:
        if depth >= MAX_ARRAY_DEPTH:
            raise GGUFError("GGUF metadata arrays are nested too deeply.")
        element_type = int(reader.unpack("<I"))
        count = int(reader.unpack("<Q"))
        if count > MAX_ARRAY_ITEMS:
            raise GGUFError("GGUF metadata array exceeds the item limit.")
        return [_read_value(reader, element_type, depth + 1) for _ in range(count)]
    raise GGUFError(f"Unsupported GGUF metadata value type: {value_type}")


def parse_gguf(source: Path | BinaryIO) -> GGUFMetadata:
    """Parse GGUF key-value metadata and stop before tensor information."""

    should_close = isinstance(source, Path)
    handle = source.open("rb") if should_close else source
    try:
        reader = _Reader(handle)
        if reader.read_exact(4) != b"GGUF":
            raise GGUFError("File does not have a GGUF header.")
        version = int(reader.unpack("<I"))
        if version not in {2, 3}:
            raise GGUFError(f"Unsupported GGUF version: {version}")
        tensor_count = int(reader.unpack("<Q"))
        metadata_count = int(reader.unpack("<Q"))
        if metadata_count > MAX_METADATA_ITEMS:
            raise GGUFError("GGUF metadata contains too many entries.")

        values: dict[str, object] = {}
        for _ in range(metadata_count):
            key = reader.string()
            if key in values:
                raise GGUFError(f"Duplicate GGUF metadata key: {key}")
            value_type = int(reader.unpack("<I"))
            values[key] = _read_value(reader, value_type)
        return GGUFMetadata(
            version=version,
            tensor_count=tensor_count,
            metadata_count=metadata_count,
            values=values,
            bytes_read=reader.bytes_read,
        )
    finally:
        if should_close:
            handle.close()


def parse_gguf_bytes(data: bytes) -> GGUFMetadata:
    return parse_gguf(io.BytesIO(data))


def inspect_template(template: str) -> list[str]:
    """Return concrete heuristic warnings without rendering the template."""

    warnings: list[str] = []
    checks = (
        (r"(?i)https?://|ftp://", "The template contains an external link."),
        (r"(?i)\b(exec|eval|import|subprocess|os\.system|popen|curl|wget)\b", "The template contains an execution or download term."),
        (r"(?i)ignore\s+(all\s+)?previous|override\s+(the\s+)?system", "The template contains an instruction-override phrase."),
        (r"__\w+__", "The template contains a double-underscore expression."),
    )
    for pattern, message in checks:
        if re.search(pattern, template):
            warnings.append(message)
    control_blocks = len(re.findall(r"{%.*?%}", template, flags=re.DOTALL))
    if control_blocks > 50:
        warnings.append(f"The template contains {control_blocks} control blocks.")
    return warnings


def template_sha256(template: str) -> str:
    return hashlib.sha256(template.encode("utf-8")).hexdigest()

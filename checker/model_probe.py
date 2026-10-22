"""Safe model-file and chat-template inventory."""

from __future__ import annotations

import hashlib
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path

from .findings import Finding
from .gguf_metadata import GGUFError, inspect_template, parse_gguf, template_sha256
from .redaction import redact_text


MODEL_SUFFIXES = {".gguf", ".safetensors", ".pkl", ".pickle", ".pt", ".pth"}
TEMPLATE_SUFFIXES = {".jinja", ".jinja2", ".j2"}
EXCLUDED_DIRECTORIES = {".git", ".venv", "node_modules", "vendor", "reports", ".state"}
MAX_DISCOVERED_FILES = 100_000
MAX_MODEL_FILES = 5_000
MAX_HASH_BYTES = 64 * 1_048_576
MAX_TEMPLATE_BYTES = 1_048_576


@dataclass
class ModelSnapshot:
    inventory: list[dict[str, object]] = field(default_factory=list)
    templates: list[dict[str, object]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    cancelled: bool = False


def inspect_models(
    code_paths: list[Path],
    model_paths: list[Path],
    previous_template_hashes: dict[str, str] | None = None,
    cancel_event: threading.Event | None = None,
) -> ModelSnapshot:
    snapshot = ModelSnapshot()
    previous = previous_template_hashes or {}
    cancellation = cancel_event or threading.Event()
    roots = list(dict.fromkeys(code_paths + model_paths))

    model_files: list[Path] = []
    template_files: list[Path] = []
    seen_files = 0
    for root in roots:
        for directory, names, files in os.walk(root):
            names[:] = [name for name in names if name not in EXCLUDED_DIRECTORIES]
            seen_files += len(files)
            if cancellation.is_set():
                snapshot.cancelled = True
                return snapshot
            if seen_files > MAX_DISCOVERED_FILES:
                snapshot.errors.append(
                    f"File discovery stopped after {MAX_DISCOVERED_FILES} entries under the selected roots."
                )
                break
            for name in files:
                path = Path(directory) / name
                suffix = path.suffix.lower()
                if suffix in MODEL_SUFFIXES and len(model_files) < MAX_MODEL_FILES:
                    model_files.append(path)
                if suffix in TEMPLATE_SUFFIXES or "chat_template" in name.lower():
                    template_files.append(path)

    for path in sorted(set(model_files)):
        if cancellation.is_set():
            snapshot.cancelled = True
            return snapshot
        _inspect_model_file(path, snapshot, previous)

    for path in sorted(set(template_files)):
        if cancellation.is_set():
            snapshot.cancelled = True
            return snapshot
        _inspect_template_file(path, snapshot, previous)
    return snapshot


def _inspect_model_file(
    path: Path, snapshot: ModelSnapshot, previous_template_hashes: dict[str, str]
) -> None:
    try:
        stat = path.stat()
    except OSError as exc:
        snapshot.errors.append(f"Could not stat {path}: {redact_text(str(exc))}")
        return
    record: dict[str, object] = {
        "path": str(path),
        "format": path.suffix.lower().lstrip("."),
        "size_bytes": stat.st_size,
        "sha256": None,
        "digest_status": "not hashed because the file exceeds the default limit",
        "provenance": "unverified without an approved reference digest",
    }
    if stat.st_size <= MAX_HASH_BYTES:
        try:
            record["sha256"] = _file_sha256(path)
            record["digest_status"] = "calculated"
        except OSError as exc:
            snapshot.errors.append(f"Could not hash {path}: {redact_text(str(exc))}")

    if path.suffix.lower() in {".pkl", ".pickle", ".pt", ".pth"}:
        snapshot.findings.append(
            Finding(
                layer=1,
                severity="low",
                status="unverified",
                asset=str(path),
                title="Model-related file uses a deserialisation-capable format",
                description=(
                    "This file format may permit executable deserialisation when loaded by unsafe APIs. "
                    "The checker did not open or execute the file."
                ),
                evidence=[f"Inventory found {path.suffix.lower()} file {path} with size {stat.st_size} bytes."],
                source="template-inspection",
                confidence="high",
                recommendation="Confirm the loader API and replace the file with a non-executable format when practical.",
                verification="Trace the file to its loader and confirm the approved digest without deserialising it during audit.",
                risk_if_accepted="An untrusted file may execute code if a permissive loader opens it.",
                fingerprint=f"model-format|{path}|{path.suffix.lower()}",
            )
        )

    if path.suffix.lower() == ".gguf":
        try:
            metadata = parse_gguf(path)
            record["gguf_version"] = metadata.version
            record["gguf_metadata_count"] = metadata.metadata_count
            record["gguf_tensor_count"] = metadata.tensor_count
            if metadata.chat_template is not None:
                digest = template_sha256(metadata.chat_template)
                record["chat_template_sha256"] = digest
                record["chat_template_bytes"] = len(metadata.chat_template.encode("utf-8"))
                template_record = {
                    "path": str(path),
                    "source": "GGUF tokenizer.chat_template metadata",
                    "sha256": digest,
                    "warnings": inspect_template(metadata.chat_template),
                }
                snapshot.templates.append(template_record)
                _template_findings(path, digest, template_record["warnings"], snapshot, previous_template_hashes)
        except GGUFError as exc:
            snapshot.errors.append(f"Could not parse GGUF metadata for {path}: {exc}")
    snapshot.inventory.append(record)


def _inspect_template_file(
    path: Path, snapshot: ModelSnapshot, previous_template_hashes: dict[str, str]
) -> None:
    try:
        size = path.stat().st_size
        if size > MAX_TEMPLATE_BYTES:
            snapshot.errors.append(f"Skipped oversized template {path} with {size} bytes.")
            return
        template = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        snapshot.errors.append(f"Could not read template {path}: {redact_text(str(exc))}")
        return
    digest = template_sha256(template)
    warnings = inspect_template(template)
    snapshot.templates.append(
        {
            "path": str(path),
            "source": "standalone template",
            "sha256": digest,
            "warnings": warnings,
        }
    )
    _template_findings(path, digest, warnings, snapshot, previous_template_hashes)


def _template_findings(
    path: Path,
    digest: str,
    warnings: object,
    snapshot: ModelSnapshot,
    previous_template_hashes: dict[str, str],
) -> None:
    warning_list = [str(item) for item in warnings] if isinstance(warnings, list) else []
    if warning_list:
        snapshot.findings.append(
            Finding(
                layer=2,
                severity="medium",
                status="suspected",
                asset=str(path),
                title="Chat template contains review-worthy instructions",
                description="Static template checks found content that needs human review. The checker did not render the template.",
                evidence=[f"{path}: {message}" for message in warning_list]
                + [f"Template SHA-256: {digest}"],
                source="template-inspection",
                confidence="medium",
                recommendation="Review the inert template text, compare it with the approved source and remove unexpected instructions.",
                verification="Record the approved template digest and repeat metadata inspection without rendering the template.",
                risk_if_accepted="Unexpected template instructions may alter model or agent behaviour.",
                fingerprint=f"template-warning|{path}|{'|'.join(warning_list)}",
            )
        )
    previous_digest = previous_template_hashes.get(str(path))
    if previous_digest and previous_digest != digest:
        snapshot.findings.append(
            Finding(
                layer=2,
                severity="medium",
                status="unverified",
                asset=str(path),
                title="Chat template changed since the previous comparable scan",
                description="The template digest differs from the last completed comparable scan. The change may be intended and needs review.",
                evidence=[f"Previous SHA-256: {previous_digest}", f"Current SHA-256: {digest}"],
                source="template-inspection",
                confidence="high",
                recommendation="Compare the template with its approved source and document the reason for the change.",
                verification="Approve the current content, record its digest and repeat the scan.",
                risk_if_accepted="An unexplained template change may alter role handling or introduce hidden instructions.",
                fingerprint=f"template-change|{path}|{previous_digest}|{digest}",
            )
        )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1_048_576):
            digest.update(chunk)
    return digest.hexdigest()

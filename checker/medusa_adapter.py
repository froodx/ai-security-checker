"""Run the pinned MEDUSA executable and convert its JSON report."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .findings import Finding, normalise_severity, utc_now
from .redaction import redact_command, redact_text


LogCallback = Callable[[str], None]


@dataclass
class MedusaResult:
    target: Path
    mode: str
    command: list[str]
    version: str
    exit_code: int | None
    duration_seconds: float
    cancelled: bool = False
    timed_out: bool = False
    findings: list[Finding] = field(default_factory=list)
    missing_linters: list[str] = field(default_factory=list)
    report_paths: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.cancelled and not self.timed_out and self.exit_code == 0


class MedusaAdapter:
    def __init__(
        self,
        executable: Path,
        state_home: Path,
        log: LogCallback,
        cancel_event: threading.Event,
    ) -> None:
        self.executable = executable
        self.state_home = state_home
        self.log = log
        self.cancel_event = cancel_event
        self._process_lock = threading.Lock()
        self._active_process: subprocess.Popen[bytes] | None = None

    def _environment(self) -> dict[str, str]:
        self.state_home.mkdir(mode=0o700, parents=True, exist_ok=True)
        environment = {
            "HOME": str(self.state_home),
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
            "NO_COLOR": "1",
            "CI": "1",
            "PYTHONUTF8": "1",
        }
        return environment

    def version(self) -> str:
        try:
            result = subprocess.run(
                [str(self.executable), "--version"],
                check=False,
                capture_output=True,
                text=True,
                timeout=15,
                env=self._environment(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return f"unavailable: {redact_text(str(exc))}"
        value = (result.stdout or result.stderr).strip()
        return redact_text(value) or f"exit {result.returncode}"

    def cancel_active(self, grace_seconds: float = 3.0) -> None:
        with self._process_lock:
            process = self._active_process
        if process is None or process.poll() is not None:
            return
        self.log("Stopping the active MEDUSA process group.")
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + grace_seconds
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        if process.poll() is None:
            self.log("MEDUSA did not stop within the grace period. Sending SIGKILL.")
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def run(
        self,
        target: Path,
        output_dir: Path,
        mode: str,
        use_quick: bool,
        timeout_seconds: int,
        include_html: bool,
    ) -> MedusaResult:
        output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        output_dir.parent.chmod(0o700)
        command = [
            str(self.executable),
            "scan",
            str(target),
            "--workers",
            "2",
            "--output",
            str(output_dir),
            "--format",
            "json",
        ]
        if include_html:
            command.extend(["--format", "html"])
        command.append("--quick" if use_quick else "--force")

        safe_command = redact_command(command)
        self.log(f"Running MEDUSA for {target} in {'quick' if use_quick else 'full'} static mode.")
        started = time.monotonic()
        cancelled = False
        timed_out = False
        exit_code: int | None = None
        stdout_text = ""
        stderr_text = ""

        try:
            with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
                process = subprocess.Popen(
                    command,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    env=self._environment(),
                    start_new_session=True,
                )
                with self._process_lock:
                    self._active_process = process
                deadline = started + timeout_seconds
                while process.poll() is None:
                    if self.cancel_event.is_set():
                        cancelled = True
                        self.cancel_active()
                        break
                    if time.monotonic() >= deadline:
                        timed_out = True
                        self.log(f"MEDUSA exceeded its {timeout_seconds}-second time limit.")
                        self.cancel_active()
                        break
                    time.sleep(0.1)
                exit_code = process.wait(timeout=5)
                stdout_file.seek(0)
                stderr_file.seek(0)
                stdout_text = stdout_file.read().decode("utf-8", errors="replace")
                stderr_text = stderr_file.read().decode("utf-8", errors="replace")
        except (OSError, subprocess.SubprocessError) as exc:
            stderr_text = f"Could not run MEDUSA: {exc}"
        finally:
            with self._process_lock:
                self._active_process = None

        _write_private_text(output_dir / "stdout.redacted.txt", redact_text(stdout_text))
        _write_private_text(output_dir / "stderr.redacted.txt", redact_text(stderr_text))
        sanitised_paths, sanitise_warnings = sanitise_report_files(output_dir)
        findings, missing_linters, parse_warnings = parse_medusa_reports(output_dir, target)

        warnings = sanitise_warnings + parse_warnings
        if cancelled:
            warnings.append("MEDUSA was cancelled before it completed.")
        elif timed_out:
            warnings.append("MEDUSA timed out before it completed.")
        elif exit_code != 0:
            warnings.append(f"MEDUSA exited with code {exit_code}.")
        if stderr_text.strip():
            warnings.append("MEDUSA wrote diagnostic output. See stderr.redacted.txt.")

        return MedusaResult(
            target=target,
            mode=mode,
            command=safe_command,
            version=self.version(),
            exit_code=exit_code,
            duration_seconds=round(time.monotonic() - started, 3),
            cancelled=cancelled,
            timed_out=timed_out,
            findings=findings,
            missing_linters=missing_linters,
            report_paths=sanitised_paths,
            warnings=list(dict.fromkeys(warnings)),
        )


def _write_private_text(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)


def sanitise_report_files(directory: Path) -> tuple[list[str], list[str]]:
    """Redact MEDUSA text reports and apply private file permissions."""

    paths: list[str] = []
    warnings: list[str] = []
    for path in sorted(directory.rglob("*")):
        if path.is_dir():
            path.chmod(0o700)
            continue
        if not path.is_file():
            continue
        path.chmod(0o600)
        paths.append(str(path.relative_to(directory.parent)))
        if path.suffix.lower() not in {".json", ".html", ".md", ".txt", ".csv", ".jsonl"}:
            continue
        try:
            if path.stat().st_size > 64 * 1_048_576:
                warnings.append(f"Skipped redaction for oversized MEDUSA file {path.name}.")
                continue
            original = path.read_text(encoding="utf-8", errors="replace")
            redacted = redact_text(original)
            if redacted != original:
                path.write_text(redacted, encoding="utf-8")
                path.chmod(0o600)
        except OSError as exc:
            warnings.append(f"Could not sanitise {path.name}: {redact_text(str(exc))}")
    return paths, warnings


def parse_medusa_reports(
    directory: Path, target: Path
) -> tuple[list[Finding], list[str], list[str]]:
    reports = sorted(directory.glob("medusa-scan-*.json"))
    if not reports:
        return [], [], ["MEDUSA did not produce a JSON report."]
    report = reports[-1]
    try:
        data = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], [], [f"Could not parse MEDUSA JSON: {redact_text(str(exc))}"]
    if not isinstance(data, dict):
        return [], [], ["MEDUSA JSON has an unexpected top-level value."]

    raw_findings = data.get("findings", [])
    if not isinstance(raw_findings, list):
        raw_findings = []
    findings: list[Finding] = []
    observed = utc_now()
    for raw in raw_findings:
        if not isinstance(raw, dict):
            continue
        findings.append(_convert_finding(raw, target, observed))

    summary = data.get("scan_summary", {})
    missing = summary.get("missing_linters", []) if isinstance(summary, dict) else []
    missing_linters = [str(item) for item in missing] if isinstance(missing, list) else []
    return findings, missing_linters, []


def _convert_finding(raw: dict[str, Any], target: Path, observed: str) -> Finding:
    scanner = str(raw.get("scanner") or "unknown")
    rule_id = str(raw.get("rule_id") or "unlabelled")
    issue = _single_line(str(raw.get("issue") or "MEDUSA reported a possible issue."), 500)
    file_value = str(raw.get("file") or target)
    line = raw.get("line") or 0
    layer = _infer_layer(scanner, rule_id, issue, file_value)
    upstream = str(raw.get("severity") or "UNDEFINED")
    severity = normalise_severity(upstream)
    confidence_value = str(raw.get("confidence") or "MEDIUM").lower()
    confidence = confidence_value if confidence_value in {"high", "medium", "low"} else "medium"
    code = _single_line(str(raw.get("code") or ""), 500)
    evidence = [f"{file_value}:{line}; scanner={scanner}; rule={rule_id}"]
    if code:
        evidence.append(f"Redacted MEDUSA excerpt: {code}")
    recommendation, verification, residual = _layer_guidance(layer)
    title = f"MEDUSA {rule_id} finding"
    fingerprint = "|".join(
        ["MEDUSA", str(layer), str(target), file_value, str(line), scanner, rule_id]
    )
    return Finding(
        layer=layer,
        severity=severity,
        status="suspected",
        asset=str(target),
        title=title,
        description=issue,
        evidence=evidence,
        source="MEDUSA",
        confidence=confidence,
        recommendation=recommendation,
        verification=verification,
        risk_if_accepted=residual,
        fingerprint=fingerprint,
        first_seen=observed,
        last_seen=observed,
        upstream_severity=upstream,
    )


def _single_line(value: str, limit: int) -> str:
    return redact_text(" ".join(value.split()))[:limit]


def _infer_layer(scanner: str, rule_id: str, issue: str, file_value: str) -> int:
    text = " ".join([scanner, rule_id, issue, file_value]).lower()
    if any(term in text for term in ("chat template", "jinja", "prompt template")):
        return 2
    if any(term in text for term in ("docker", "network", "bind", "cors", "api auth")):
        return 4
    if any(term in text for term in ("pickle", "deserial", "model download", "safetensor", "gguf", "huggingface")):
        return 1
    if any(term in text for term in ("runner", "cuda", "torch.load", "model load")):
        return 3
    return 5


def _layer_guidance(layer: int) -> tuple[str, str, str]:
    guidance = {
        1: (
            "Confirm the model or download source, require a trusted digest and remove unsafe loading paths.",
            "Repeat the scan and compare the model source and digest with the approved reference.",
            "An untrusted model or loader may still execute unsafe deserialisation or supply altered content.",
        ),
        2: (
            "Review the template as inert text and restrict unexpected instructions, links and control flow.",
            "Hash the approved template and repeat metadata inspection without rendering it.",
            "Static review may miss a trigger or a runtime template override.",
        ),
        3: (
            "Confirm the runner version, executable source, launch settings and loading permissions.",
            "Restart only after approval, then record the executable version and launch configuration.",
            "The runner may retain unsafe behaviour or an unverified dependency.",
        ),
        4: (
            "Restrict the listener or container publish rule and require authentication where access is needed.",
            "Check the listener, container binding and effective firewall after an approved change.",
            "The service may remain reachable by unauthorised local or network clients.",
        ),
        5: (
            "Reduce agent tool authority or validate untrusted input before it reaches the reported operation.",
            "Run focused tests that prove denied input cannot reach the affected tool or command.",
            "A crafted prompt or dependency may still use the agent's granted authority.",
        ),
    }
    return guidance[layer]

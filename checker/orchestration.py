"""Scan orchestration, cancellation, coverage and baseline comparison."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from .config import PROJECT_ROOT
from .findings import Coverage, Finding, deduplicate, utc_now
from .medusa_adapter import MedusaAdapter, MedusaResult
from .model_probe import ModelSnapshot, inspect_models
from .redaction import redact_text
from .reports import LAYER_NAMES, write_all_reports, write_json, write_text
from .runtime_probe import RuntimeProbe, RuntimeSnapshot


ProgressCallback = Callable[[dict[str, Any]], None]


@dataclass(frozen=True)
class ScanRequest:
    paths: list[Path]
    model_paths: list[Path]
    mode: str
    label: str


@dataclass
class ScanOutcome:
    status: str
    report_dir: Path
    findings: list[Finding]
    coverage: list[Coverage]
    exit_code: int


class ScanRunner:
    def __init__(
        self,
        project_root: Path = PROJECT_ROOT,
        medusa_executable: Path | None = None,
        progress: ProgressCallback | None = None,
        runtime_probe: RuntimeProbe | None = None,
        timeouts: dict[str, int] | None = None,
    ) -> None:
        self.project_root = project_root.resolve()
        self.report_root = self.project_root / "reports"
        self.state_root = self.project_root / ".state"
        self.medusa_executable = medusa_executable or self.project_root / ".venv" / "bin" / "medusa"
        self.progress_callback = progress or (lambda _value: None)
        self.runtime_probe = runtime_probe or RuntimeProbe()
        self.timeouts = timeouts or {"basic": 900, "medium": 3600, "full": 7200}
        self.cancel_event = threading.Event()
        self._adapter: MedusaAdapter | None = None
        self._log_path: Path | None = None
        self._completed_steps = 0
        self._total_steps = 0

    def cancel(self) -> None:
        self.cancel_event.set()
        if self._adapter is not None:
            self._adapter.cancel_active()

    def run(self, request: ScanRequest) -> ScanOutcome:
        if request.mode not in {"basic", "medium", "full"}:
            raise ValueError(f"Unsupported mode: {request.mode}")
        self.cancel_event.clear()
        fingerprint = _target_fingerprint(request.paths, request.model_paths)
        previous_dir = find_previous_report(self.report_root, fingerprint, request.mode)
        previous_findings = _load_previous_findings(previous_dir)
        previous_hashes = _load_previous_template_hashes(previous_dir)
        report_dir = self._create_report_dir(request.label)
        self._log_path = report_dir / "scan-log.txt"
        self._log_path.touch(mode=0o600)
        self._log_path.chmod(0o600)

        started_at = utc_now()
        self._total_steps = len(request.paths) + 3
        self._completed_steps = 0
        self._progress("Preparing scan", "running", report_dir)
        self._log(
            f"Started {request.mode} scan for {len(request.paths)} code path(s) and "
            f"{len(request.model_paths)} model path(s)."
        )

        self.state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        medusa_home = self.state_root / "medusa-home"
        medusa_home.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._adapter = MedusaAdapter(
            self.medusa_executable,
            medusa_home,
            self._log,
            self.cancel_event,
        )
        medusa_results: list[MedusaResult] = []
        has_baseline = previous_dir is not None
        use_quick = request.mode == "basic" and has_baseline
        if request.mode == "basic" and not has_baseline:
            self._log("No completed comparable baseline exists. Basic mode will run a full static scan.")

        for index, target in enumerate(request.paths, start=1):
            if self.cancel_event.is_set():
                break
            self._progress(f"MEDUSA scan {index} of {len(request.paths)}", "running", report_dir)
            medusa_dir = report_dir / "medusa" / f"{index:02d}-{_slug(target.name)}"
            result = self._adapter.run(
                target=target,
                output_dir=medusa_dir,
                mode=request.mode,
                use_quick=use_quick,
                timeout_seconds=self.timeouts[request.mode],
                include_html=request.mode in {"medium", "full"},
            )
            medusa_results.append(result)
            self._completed_steps += 1
            self._log(
                f"MEDUSA finished for {target} with exit code {result.exit_code} and "
                f"{len(result.findings)} finding(s)."
            )

        runtime = RuntimeSnapshot()
        if not self.cancel_event.is_set():
            self._progress("Inspecting local runtime", "running", report_dir)
            try:
                runtime = self.runtime_probe.inspect(request.paths)
            except Exception as exc:
                runtime.errors.append(f"Runtime inspection failed: {redact_text(str(exc))}")
            self._completed_steps += 1
            self._log(
                f"Runtime inspection recorded {len(runtime.findings)} finding(s) and "
                f"{len(runtime.errors)} coverage warning(s)."
            )

        models = ModelSnapshot()
        if not self.cancel_event.is_set():
            self._progress("Inspecting model files and templates", "running", report_dir)
            try:
                models = inspect_models(
                    request.paths,
                    request.model_paths,
                    previous_template_hashes=previous_hashes,
                    cancel_event=self.cancel_event,
                )
            except Exception as exc:
                models.errors.append(f"Model inspection failed: {redact_text(str(exc))}")
            self._completed_steps += 1
            self._log(
                f"Model inspection recorded {len(models.inventory)} model file(s), "
                f"{len(models.templates)} template(s) and {len(models.findings)} finding(s)."
            )

        findings = deduplicate(
            [finding for result in medusa_results for finding in result.findings]
            + runtime.findings
            + models.findings
        )
        _restore_first_seen(findings, previous_findings)
        comparison = compare_findings(findings, previous_findings)
        cancelled = self.cancel_event.is_set() or models.cancelled or any(
            result.cancelled for result in medusa_results
        )
        medusa_error = len(medusa_results) != len(request.paths) or any(
            not result.complete for result in medusa_results
        )
        if cancelled:
            status = "cancelled"
            exit_code = 130
        elif medusa_error:
            status = "error"
            exit_code = 2
        else:
            status = "completed"
            exit_code = 0

        coverage = build_coverage(request, medusa_results, runtime, models, findings, cancelled)
        finished_at = utc_now()
        medusa_version = next(
            (result.version for result in medusa_results if result.version), self._adapter.version()
        )
        metadata: dict[str, Any] = {
            "started_at": started_at,
            "finished_at": finished_at,
            "status": status,
            "mode": request.mode,
            "label": request.label,
            "targets": [str(path) for path in request.paths],
            "model_paths": [str(path) for path in request.model_paths],
            "target_fingerprint": fingerprint,
            "previous_report": str(previous_dir) if previous_dir else None,
            "medusa_version": medusa_version,
            "medusa_commit": _medusa_commit(self.project_root / "medusa"),
            "medusa_runs": [
                {
                    "target": str(result.target),
                    "mode": result.mode,
                    "command": result.command,
                    "exit_code": result.exit_code,
                    "duration_seconds": result.duration_seconds,
                    "cancelled": result.cancelled,
                    "timed_out": result.timed_out,
                    "missing_linters": result.missing_linters,
                    "warnings": result.warnings,
                    "report_paths": result.report_paths,
                }
                for result in medusa_results
            ],
            "runtime_errors": runtime.errors,
            "model_errors": models.errors,
        }

        self._progress("Writing reports", "running", report_dir)
        write_json(report_dir / "runtime.json", runtime.evidence)
        write_json(
            report_dir / "model-inventory.json",
            {"models": models.inventory, "templates": models.templates, "errors": models.errors},
        )
        write_all_reports(report_dir, findings, coverage, metadata, comparison)
        write_json(report_dir / "manifest.json", metadata)
        self._completed_steps += 1
        self._write_latest(report_dir)
        self._log(f"Scan ended with status {status}. Reports are in {report_dir}.")
        self._progress("Scan finished", status, report_dir)
        return ScanOutcome(status, report_dir, findings, coverage, exit_code)

    def _create_report_dir(self, label: str) -> Path:
        self.report_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.report_root.chmod(0o700)
        timestamp = datetime.now(UTC).strftime("%Y-%m-%d_%H%M%S")
        base = self.report_root / f"{timestamp}_{_slug(label)}"
        candidate = base
        number = 1
        while candidate.exists():
            number += 1
            candidate = Path(f"{base}_{number}")
        candidate.mkdir(mode=0o700)
        return candidate

    def _log(self, message: str) -> None:
        safe = redact_text(" ".join(message.splitlines()))
        timestamp = datetime.now(UTC).replace(microsecond=0).isoformat()
        line = f"{timestamp} {safe}\n"
        if self._log_path:
            with self._log_path.open("a", encoding="utf-8") as handle:
                handle.write(line)
            self._log_path.chmod(0o600)

    def _progress(self, task: str, status: str, report_dir: Path) -> None:
        self.progress_callback(
            {
                "status": status,
                "current_task": task,
                "completed_checks": self._completed_steps,
                "total_checks": self._total_steps,
                "report_dir": str(report_dir),
            }
        )

    def _write_latest(self, report_dir: Path) -> None:
        latest = self.report_root / "latest.txt"
        write_text(latest, report_dir.name + "\n")


def build_coverage(
    request: ScanRequest,
    medusa_results: list[MedusaResult],
    runtime: RuntimeSnapshot,
    models: ModelSnapshot,
    findings: list[Finding],
    cancelled: bool,
) -> list[Coverage]:
    if cancelled:
        return [
            Coverage(
                layer=layer,
                name=LAYER_NAMES[layer],
                status="cancelled",
                reason="The scan was cancelled. Completed evidence may be partial and no layer is marked passed.",
                limitations=["Run a new scan to obtain complete coverage."],
            )
            for layer in range(1, 6)
        ]

    complete_medusa = len(medusa_results) == len(request.paths) and all(
        result.complete for result in medusa_results
    )
    missing_linters = sorted(
        {name for result in medusa_results for name in result.missing_linters}
    )
    by_layer = {layer: [item for item in findings if item.layer == layer] for layer in range(1, 6)}
    medusa_evidence = [
        f"MEDUSA {result.version}, exit {result.exit_code}, target {result.target}"
        for result in medusa_results
    ]

    coverage: list[Coverage] = []
    layer1_reason = (
        "Selected source and model paths were inspected, but no approved reference digest was configured for model provenance."
        if complete_medusa
        else "MEDUSA source checks did not complete for every target."
    )
    coverage.append(
        Coverage(
            1,
            LAYER_NAMES[1],
            "finding" if by_layer[1] else ("unknown" if complete_medusa else "error"),
            layer1_reason,
            evidence=medusa_evidence
            + [f"Inventoried {len(models.inventory)} model-related file(s)."],
            limitations=[
                "A digest does not prove publisher honesty.",
                "Large files above the configured limit were not hashed.",
            ],
        )
    )

    if request.mode == "basic":
        layer2_status = "finding" if by_layer[2] else "not_checked"
        layer2_reason = "Basic mode recorded available templates but defers full template review to Medium or Full mode."
    elif models.errors:
        layer2_status = "finding" if by_layer[2] else "unknown"
        layer2_reason = "Template inspection completed with coverage warnings."
    else:
        layer2_status = "finding" if by_layer[2] else "passed"
        layer2_reason = "Standalone templates and GGUF chat-template metadata under the selected roots were inspected without rendering."
    coverage.append(
        Coverage(
            2,
            LAYER_NAMES[2],
            layer2_status,
            layer2_reason,
            evidence=[f"Inspected {len(models.templates)} chat template(s)."],
            limitations=["Static heuristics may miss trigger-activated instructions and runtime overrides."],
        )
    )

    coverage.append(
        Coverage(
            3,
            LAYER_NAMES[3],
            "finding" if by_layer[3] else "unknown",
            "Runner processes, executable paths and version commands were inspected. Current CVE verification was not performed.",
            evidence=[
                f"Recorded {len(runtime.evidence.get('runner_versions', []))} runner version(s) and "
                f"{len(runtime.evidence.get('runner_processes', []))} related process(es)."
            ],
            limitations=["No current CVE database was queried, so advisory status is not checked."],
        )
    )

    layer4_findings = by_layer[4]
    runtime_network_available = "listeners" in runtime.evidence and "containers" in runtime.evidence
    if layer4_findings:
        layer4_status = "finding"
    elif runtime_network_available and not runtime.errors:
        layer4_status = "passed"
    else:
        layer4_status = "unknown"
    coverage.append(
        Coverage(
            4,
            LAYER_NAMES[4],
            layer4_status,
            "Local listeners, Docker port mappings, Compose files and available firewall state were inspected.",
            evidence=[
                f"Recorded {len(runtime.evidence.get('listeners', []))} listener(s) and "
                f"{len(runtime.evidence.get('containers', []))} running container(s)."
            ],
            limitations=[
                "Wildcard bindings do not prove public internet exposure.",
                "NAT, router and inaccessible firewall state remain unknown.",
            ]
            + runtime.errors,
        )
    )

    if by_layer[5]:
        layer5_status = "finding"
    elif not complete_medusa:
        layer5_status = "error"
    elif missing_linters:
        layer5_status = "unknown"
    elif request.mode == "full":
        layer5_status = "not_checked"
    else:
        layer5_status = "passed"
    if request.mode == "full" and not by_layer[5]:
        layer5_reason = "Static MEDUSA checks completed. Behavioural tests need separate approval and a disposable target, so they were not run."
    else:
        layer5_reason = "MEDUSA inspected agent source, AI configuration and tool wrappers."
    coverage.append(
        Coverage(
            5,
            LAYER_NAMES[5],
            layer5_status,
            layer5_reason,
            evidence=medusa_evidence,
            limitations=(
                [f"Missing optional MEDUSA linters: {', '.join(missing_linters)}"]
                if missing_linters
                else []
            )
            + ["Static analysis cannot prove that model behaviour has no hidden trigger."],
        )
    )
    return coverage


def find_previous_report(report_root: Path, fingerprint: str, mode: str) -> Path | None:
    if not report_root.exists():
        return None
    ranks = {"basic": 1, "medium": 2, "full": 3}
    required = ranks[mode]
    for directory in sorted((path for path in report_root.iterdir() if path.is_dir()), reverse=True):
        manifest = directory / "manifest.json"
        try:
            data = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        previous_mode = str(data.get("mode") or "")
        if data.get("status") != "completed" or data.get("target_fingerprint") != fingerprint:
            continue
        if mode != "basic" and ranks.get(previous_mode, 0) < required:
            continue
        return directory
    return None


def compare_findings(
    findings: list[Finding], previous: dict[str, dict[str, Any]]
) -> dict[str, list[str]]:
    current_ids = {finding.id for finding in findings}
    previous_ids = set(previous)
    return {
        "new": sorted(current_ids - previous_ids),
        "unchanged": sorted(current_ids & previous_ids),
        "resolved": sorted(previous_ids - current_ids),
    }


def _load_previous_findings(report_dir: Path | None) -> dict[str, dict[str, Any]]:
    if report_dir is None:
        return {}
    try:
        values = json.loads((report_dir / "findings.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(values, list):
        return {}
    return {
        str(item["id"]): item
        for item in values
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def _load_previous_template_hashes(report_dir: Path | None) -> dict[str, str]:
    if report_dir is None:
        return {}
    try:
        data = json.loads((report_dir / "model-inventory.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    templates = data.get("templates", []) if isinstance(data, dict) else []
    return {
        str(item["path"]): str(item["sha256"])
        for item in templates
        if isinstance(item, dict) and item.get("path") and item.get("sha256")
    }


def _restore_first_seen(
    findings: list[Finding], previous: dict[str, dict[str, Any]]
) -> None:
    for finding in findings:
        prior = previous.get(finding.id)
        if prior and isinstance(prior.get("first_seen"), str):
            finding.first_seen = prior["first_seen"]


def _target_fingerprint(paths: list[Path], model_paths: list[Path]) -> str:
    value = "\0".join(str(path) for path in sorted(paths + model_paths))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _medusa_commit(path: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    value = result.stdout.strip()
    return value if result.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", value) else "unknown"


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:60] or "scan"

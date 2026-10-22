"""Loopback-only Flask interface with one cancellable scan worker."""

from __future__ import annotations

import atexit
import json
import secrets
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, abort, jsonify, render_template, request, send_file

from .config import CheckerConfig, ConfigurationError, PROJECT_ROOT, load_config, select_paths
from .orchestration import ScanRequest, ScanRunner
from .redaction import redact_text


class ScanManager:
    def __init__(self, config: CheckerConfig) -> None:
        self.config = config
        self._lock = threading.Lock()
        self._runner: ScanRunner | None = None
        self._thread: threading.Thread | None = None
        self._started = 0.0
        self._state: dict[str, object] = {
            "status": "idle",
            "current_task": "No scan is running",
            "completed_checks": 0,
            "total_checks": 0,
            "report_dir": None,
            "error": None,
        }
        self._load_latest()

    def start(self, scan_request: ScanRequest) -> bool:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._state = {
                "status": "running",
                "current_task": "Starting scan",
                "completed_checks": 0,
                "total_checks": len(scan_request.paths) + 3,
                "report_dir": None,
                "error": None,
            }
            self._started = time.monotonic()
            self._runner = ScanRunner(progress=self._update)
            self._thread = threading.Thread(
                target=self._work,
                args=(self._runner, scan_request),
                name="ai-security-check-scan",
                daemon=True,
            )
            self._thread.start()
            return True

    def _work(self, runner: ScanRunner, scan_request: ScanRequest) -> None:
        try:
            outcome = runner.run(scan_request)
            self._update(
                {
                    "status": outcome.status,
                    "current_task": "Scan finished",
                    "completed_checks": len(scan_request.paths) + 3,
                    "total_checks": len(scan_request.paths) + 3,
                    "report_dir": str(outcome.report_dir),
                }
            )
        except Exception as exc:
            with self._lock:
                self._state["status"] = "error"
                self._state["current_task"] = "Scan failed"
                self._state["error"] = redact_text(str(exc))

    def _update(self, values: dict[str, object]) -> None:
        with self._lock:
            self._state.update(values)

    def cancel(self) -> bool:
        with self._lock:
            runner = self._runner
            active = self._thread is not None and self._thread.is_alive()
            if active:
                self._state["status"] = "cancelling"
                self._state["current_task"] = "Stopping active checks"
        if runner is not None and active:
            runner.cancel()
            return True
        return False

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            state = dict(self._state)
        state["elapsed_seconds"] = (
            round(time.monotonic() - self._started, 1)
            if state.get("status") in {"running", "cancelling"}
            else 0
        )
        report_dir_value = state.get("report_dir")
        if report_dir_value:
            report_dir = Path(str(report_dir_value))
            state["run_id"] = report_dir.name
            state["logs"] = _tail(report_dir / "scan-log.txt", 300)
            state["findings"] = _load_json(report_dir / "findings.json", [])
            state["coverage"] = _load_json(report_dir / "coverage.json", [])
            state["report_files"] = [
                str(path.relative_to(report_dir))
                for path in sorted(report_dir.rglob("*"))
                if path.is_file()
            ]
        else:
            state.update({"run_id": None, "logs": [], "findings": [], "coverage": [], "report_files": []})
        return state

    def shutdown(self) -> None:
        self.cancel()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=5)

    def _load_latest(self) -> None:
        latest = PROJECT_ROOT / "reports" / "latest.txt"
        try:
            name = latest.read_text(encoding="utf-8").strip()
            report_dir = (PROJECT_ROOT / "reports" / name).resolve(strict=True)
            manifest = _load_json(report_dir / "manifest.json", {})
            self._state.update(
                {
                    "status": manifest.get("status", "idle"),
                    "current_task": "Last completed run",
                    "report_dir": str(report_dir),
                }
            )
        except (OSError, ValueError):
            return


def create_app(config_path: Path | None = None) -> Flask:
    config = load_config(config_path)
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=64 * 1024, JSON_SORT_KEYS=True)
    csrf_token = secrets.token_urlsafe(32)
    manager = ScanManager(config)
    app.extensions["scan_manager"] = manager
    app.extensions["csrf_token"] = csrf_token
    atexit.register(manager.shutdown)

    @app.before_request
    def restrict_request() -> None:
        hostname = (request.host.split(":", 1)[0]).strip("[]").lower()
        if hostname not in {"127.0.0.1", "localhost"}:
            abort(403)
        origin = request.headers.get("Origin")
        if origin and urlparse(origin).hostname not in {"127.0.0.1", "localhost"}:
            abort(403)
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if not request.is_json or not secrets.compare_digest(
                request.headers.get("X-ASC-Token", ""), csrf_token
            ):
                abort(403)

    @app.get("/")
    def index() -> str:
        targets = [
            {"name": name, "label": target.label}
            for name, target in sorted(config.targets.items())
        ]
        return render_template("index.html", token=csrf_token, targets=targets)

    @app.get("/api/status")
    def status():
        return jsonify(manager.snapshot())

    @app.post("/api/scans")
    def start_scan():
        data = request.get_json(silent=False)
        if not isinstance(data, dict):
            return jsonify({"error": "The request must contain a JSON object."}), 400
        target_name = data.get("target") if isinstance(data.get("target"), str) else None
        paths = data.get("paths", [])
        model_paths = data.get("model_paths", [])
        mode = str(data.get("mode") or "basic")
        if mode not in {"basic", "medium", "full"}:
            return jsonify({"error": "Unsupported mode."}), 400
        if not isinstance(paths, list) or not all(isinstance(item, str) for item in paths):
            return jsonify({"error": "paths must be a list of strings."}), 400
        if not isinstance(model_paths, list) or not all(
            isinstance(item, str) for item in model_paths
        ):
            return jsonify({"error": "model_paths must be a list of strings."}), 400
        try:
            selected, selected_models, label = select_paths(
                config, target_name, paths, model_paths
            )
        except ConfigurationError as exc:
            return jsonify({"error": str(exc)}), 400
        started = manager.start(ScanRequest(selected, selected_models, mode, label))
        if not started:
            return jsonify({"error": "A scan is already running.", "status": "busy"}), 409
        return jsonify({"status": "started"}), 202

    @app.post("/api/cancel")
    def cancel_scan():
        return jsonify({"status": "cancelling" if manager.cancel() else "idle"})

    @app.get("/reports/<run_id>/<path:filename>")
    def report_file(run_id: str, filename: str):
        report_root = (PROJECT_ROOT / "reports").resolve(strict=False)
        candidate = (report_root / run_id / filename).resolve(strict=False)
        try:
            candidate.relative_to(report_root)
        except ValueError:
            abort(404)
        if not candidate.is_file():
            abort(404)
        return send_file(candidate, as_attachment=False, conditional=True)

    return app


def serve(host: str, port: int, config_path: Path | None = None) -> None:
    app = create_app(config_path)
    print(f"AI Security Checker UI: http://{host}:{port}")
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)


def _tail(path: Path, count: int) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return [redact_text(line) for line in lines[-count:]]


def _load_json(path: Path, default: object) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default

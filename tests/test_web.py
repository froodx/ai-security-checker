import threading
import time
from pathlib import Path
from types import SimpleNamespace

import yaml

import checker.web as web_module


class FakeRunner:
    report_root: Path

    def __init__(self, progress=None) -> None:
        self.progress = progress or (lambda _value: None)
        self.cancelled = threading.Event()

    def run(self, request):
        report = self.report_root / "2000-01-01_000000_web"
        report.mkdir(parents=True, exist_ok=True)
        self.progress(
            {
                "status": "running",
                "current_task": "Fixture scan",
                "completed_checks": 0,
                "total_checks": 4,
                "report_dir": str(report),
            }
        )
        self.cancelled.wait(5)
        return SimpleNamespace(status="cancelled", report_dir=report)

    def cancel(self) -> None:
        self.cancelled.set()


def _config(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    config = {
        "allowed_roots": [str(tmp_path)],
        "targets": {"fixture": {"label": "Fixture", "code_roots": [str(target)]}},
    }
    path = tmp_path / "targets.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return path


def test_web_rejects_nonlocal_host_and_requires_token(tmp_path: Path) -> None:
    app = web_module.create_app(_config(tmp_path))
    client = app.test_client()

    assert client.get("/", headers={"Host": "example.invalid"}).status_code == 403
    assert client.post("/api/cancel", json={}).status_code == 403


def test_web_starts_one_scan_and_cancels_it(tmp_path: Path, monkeypatch) -> None:
    FakeRunner.report_root = tmp_path / "reports"
    monkeypatch.setattr(web_module, "ScanRunner", FakeRunner)
    app = web_module.create_app(_config(tmp_path))
    token = app.extensions["csrf_token"]
    client = app.test_client()
    headers = {"X-ASC-Token": token}

    response = client.post(
        "/api/scans",
        json={"target": "fixture", "paths": [], "model_paths": [], "mode": "basic"},
        headers=headers,
    )
    assert response.status_code == 202
    busy = client.post(
        "/api/scans",
        json={"target": "fixture", "paths": [], "model_paths": [], "mode": "basic"},
        headers=headers,
    )
    assert busy.status_code == 409
    assert client.post("/api/cancel", json={}, headers=headers).status_code == 200

    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        status = client.get("/api/status").get_json()
        if status["status"] == "cancelled":
            break
        time.sleep(0.05)
    assert status["status"] == "cancelled"

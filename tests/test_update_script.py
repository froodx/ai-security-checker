import os
import shutil
import subprocess
from pathlib import Path


UPDATE_SCRIPT = Path(__file__).parents[1] / "scripts" / "update-upstream.sh"


def _run(arguments: list[str], directory: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, cwd=directory, check=True, capture_output=True, text=True)


def test_failed_smoke_test_rolls_back_disposable_checkout(tmp_path: Path) -> None:
    remote = tmp_path / "remote.git"
    source = tmp_path / "source"
    project = tmp_path / "project"
    _run(["git", "init", "--bare", str(remote)], tmp_path)
    _run(["git", "init", "-b", "main", str(source)], tmp_path)
    _run(["git", "config", "user.name", "Fixture"], source)
    _run(["git", "config", "user.email", "fixture@example.invalid"], source)
    (source / "version.txt").write_text("one\n", encoding="utf-8")
    _run(["git", "add", "version.txt"], source)
    _run(["git", "commit", "-m", "Version one"], source)
    _run(["git", "tag", "v1.0.0"], source)
    first_sha = _run(["git", "rev-parse", "HEAD"], source).stdout.strip()
    (source / "version.txt").write_text("two\n", encoding="utf-8")
    _run(["git", "commit", "-am", "Version two"], source)
    _run(["git", "tag", "v2.0.0"], source)
    _run(["git", "remote", "add", "origin", str(remote)], source)
    _run(["git", "push", "origin", "main", "--tags"], source)

    (project / "scripts").mkdir(parents=True)
    shutil.copy2(UPDATE_SCRIPT, project / "scripts" / "update-upstream.sh")
    _run(["git", "clone", str(remote), str(project / "medusa")], tmp_path)
    _run(["git", "checkout", "--detach", "v1.0.0"], project / "medusa")
    bin_dir = project / ".venv" / "bin"
    bin_dir.mkdir(parents=True)
    fake_python = bin_dir / "python"
    fake_python.write_text(
        "#!/bin/sh\n"
        "if [ \"${1:-}\" = -m ] && [ \"${2:-}\" = pytest ]; then exit 1; fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    fake_medusa = bin_dir / "medusa"
    fake_medusa.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_python.chmod(0o755)
    fake_medusa.chmod(0o755)

    result = subprocess.run(
        [
            "sh",
            str(project / "scripts" / "update-upstream.sh"),
            "--tag",
            "v2.0.0",
            "--approve",
            "--allow-unsigned",
        ],
        cwd=project,
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
    )

    current_sha = _run(["git", "rev-parse", "HEAD"], project / "medusa").stdout.strip()
    assert result.returncode == 1
    assert current_sha == first_sha
    assert "Returning MEDUSA" in result.stderr

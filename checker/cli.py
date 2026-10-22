"""Command-line entrypoint."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from . import __version__
from .config import ConfigurationError, PROJECT_ROOT, load_config, select_paths
from .orchestration import ScanRequest, ScanRunner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-security-check",
        description="Run read-only five-layer checks against local AI repositories and runtimes.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run a non-interactive local scan.")
    scan.add_argument("--target", help="Named target from config/targets.yaml.")
    scan.add_argument("--path", action="append", default=[], help="Code directory. Repeat for multiple paths.")
    scan.add_argument(
        "--model-path",
        action="append",
        default=[],
        help="Opt-in model directory under an allowed root. Repeat as needed.",
    )
    scan.add_argument("--mode", choices=("basic", "medium", "full"), default="basic")
    scan.add_argument("--config", type=Path, help="Local target configuration file.")

    web = subparsers.add_parser("web", help="Run the loopback-only web interface.")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8765)
    web.add_argument("--config", type=Path, help="Local target configuration file.")

    subparsers.add_parser(
        "upstream-check", help="Compare the pinned MEDUSA tag with upstream without updating it."
    )
    subparsers.add_parser("targets", help="List configured target names and labels.")
    return parser


def main(arguments: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(arguments)
    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "web":
            return _web(args)
        if args.command == "upstream-check":
            return subprocess.call([str(PROJECT_ROOT / "scripts" / "check-upstream.sh")])
        if args.command == "targets":
            config = load_config()
            for name, target in config.targets.items():
                print(f"{name}\t{target.label}")
            return 0
    except ConfigurationError as exc:
        parser.error(str(exc))
    return 2


def _refuse_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise ConfigurationError("The checker must not run as root.")


def _scan(args: argparse.Namespace) -> int:
    _refuse_root()
    config = load_config(args.config)
    paths, model_paths, label = select_paths(
        config, args.target, args.path, args.model_path
    )
    runner = ScanRunner()
    outcome = runner.run(
        ScanRequest(paths=paths, model_paths=model_paths, mode=args.mode, label=label)
    )
    print(f"Status: {outcome.status}")
    print(f"Report: {outcome.report_dir}")
    print(f"Findings: {len(outcome.findings)}")
    return outcome.exit_code


def _web(args: argparse.Namespace) -> int:
    _refuse_root()
    if args.host not in {"127.0.0.1", "localhost"}:
        raise ConfigurationError("The web interface may bind only to 127.0.0.1 or localhost.")
    if not 1 <= args.port <= 65535:
        raise ConfigurationError("The port must be between 1 and 65535.")
    from .web import serve

    serve(host="127.0.0.1", port=args.port, config_path=args.config)
    return 0


if __name__ == "__main__":
    sys.exit(main())

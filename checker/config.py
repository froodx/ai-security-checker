"""Configuration and allowlisted path handling."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "targets.yaml"


class ConfigurationError(ValueError):
    """Raised when configuration or a requested path is unsafe."""


@dataclass(frozen=True)
class Target:
    name: str
    label: str
    code_roots: tuple[Path, ...]
    focus_paths: tuple[Path, ...] = ()
    model_paths: tuple[Path, ...] = ()
    runtime: str = "local"


@dataclass(frozen=True)
class CheckerConfig:
    allowed_roots: tuple[Path, ...]
    targets: dict[str, Target] = field(default_factory=dict)


def _expand_path(value: str | Path) -> Path:
    if not isinstance(value, (str, Path)):
        raise ConfigurationError("A configured path must be a string.")
    return Path(value).expanduser().resolve(strict=False)


def _path_list(value: Any, field_name: str) -> tuple[Path, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigurationError(f"{field_name} must be a list of paths.")
    return tuple(_expand_path(item) for item in value)


def _default_data() -> dict[str, Any]:
    return {
        "allowed_roots": [str(Path.home() / "code")],
        "targets": {
            "hermes": {
                "label": "Hermes on this host",
                "code_roots": [str(Path.home() / "code" / "hermes-agent")],
                "focus_paths": [str(Path.home() / "code" / "hermes-agent" / "hermes")],
                "model_paths": [],
                "runtime": "local",
            }
        },
    }


def load_config(path: Path | None = None) -> CheckerConfig:
    """Load local configuration or use the portable default target."""

    config_path = path or DEFAULT_CONFIG_PATH
    if config_path.exists():
        try:
            loaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigurationError(f"Cannot read {config_path}: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ConfigurationError("The target configuration must be a mapping.")
        data = loaded
    else:
        data = _default_data()

    allowed_roots = _path_list(data.get("allowed_roots"), "allowed_roots")
    if not allowed_roots:
        raise ConfigurationError("At least one allowed root is required.")

    raw_targets = data.get("targets", {})
    if not isinstance(raw_targets, dict):
        raise ConfigurationError("targets must be a mapping.")

    targets: dict[str, Target] = {}
    for name, raw in raw_targets.items():
        if not isinstance(name, str) or not isinstance(raw, dict):
            raise ConfigurationError("Each target must have a name and mapping value.")
        code_roots = _path_list(raw.get("code_roots"), f"targets.{name}.code_roots")
        if not code_roots:
            raise ConfigurationError(f"Target {name!r} has no code_roots.")
        targets[name] = Target(
            name=name,
            label=str(raw.get("label") or name),
            code_roots=code_roots,
            focus_paths=_path_list(raw.get("focus_paths"), f"targets.{name}.focus_paths"),
            model_paths=_path_list(raw.get("model_paths"), f"targets.{name}.model_paths"),
            runtime=str(raw.get("runtime") or "local"),
        )
    return CheckerConfig(allowed_roots=allowed_roots, targets=targets)


def is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def validate_path(path: str | Path, allowed_roots: tuple[Path, ...]) -> Path:
    """Resolve a directory and reject symlink escapes from allowed roots."""

    candidate = _expand_path(path)
    if not candidate.exists():
        raise ConfigurationError(f"Target does not exist: {candidate}")
    if not candidate.is_dir():
        raise ConfigurationError(f"Target is not a directory: {candidate}")
    if not any(is_within(candidate, root.resolve(strict=False)) for root in allowed_roots):
        raise ConfigurationError(f"Target is outside the configured roots: {candidate}")
    return candidate


def select_paths(
    config: CheckerConfig,
    target_name: str | None,
    explicit_paths: list[str],
    explicit_model_paths: list[str] | None = None,
) -> tuple[list[Path], list[Path], str]:
    """Resolve one named target or explicit paths, with a five-target limit."""

    if target_name and explicit_paths:
        raise ConfigurationError("Use either --target or --path, not both.")
    model_values = list(explicit_model_paths or [])
    if target_name:
        try:
            target = config.targets[target_name]
        except KeyError as exc:
            raise ConfigurationError(f"Unknown target: {target_name}") from exc
        requested = list(target.code_roots)
        model_values.extend(str(path) for path in target.model_paths)
        label = target.label
    elif explicit_paths:
        requested = [Path(value) for value in explicit_paths]
        label = "multiple-targets" if len(requested) > 1 else requested[0].name
    else:
        raise ConfigurationError("Choose --target or supply at least one --path.")

    if not 1 <= len(requested) <= 5:
        raise ConfigurationError("A scan must contain between one and five code paths.")
    paths = [validate_path(path, config.allowed_roots) for path in requested]
    if len(set(paths)) != len(paths):
        raise ConfigurationError("Duplicate target paths are not allowed.")

    model_paths = [validate_path(path, config.allowed_roots) for path in model_values]
    return paths, model_paths, label

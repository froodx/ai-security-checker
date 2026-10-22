from pathlib import Path

import pytest

from checker.config import CheckerConfig, ConfigurationError, select_paths, validate_path


def test_validate_path_rejects_symlink_escape(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    (allowed / "escape").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ConfigurationError, match="outside"):
        validate_path(allowed / "escape", (allowed.resolve(),))


def test_select_paths_accepts_multiple_unique_targets(tmp_path: Path) -> None:
    first = tmp_path / "one"
    second = tmp_path / "two"
    first.mkdir()
    second.mkdir()
    config = CheckerConfig(allowed_roots=(tmp_path.resolve(),), targets={})

    paths, models, label = select_paths(config, None, [str(first), str(second)], [])

    assert paths == [first.resolve(), second.resolve()]
    assert models == []
    assert label == "multiple-targets"


def test_select_paths_rejects_more_than_five_targets(tmp_path: Path) -> None:
    values = []
    for number in range(6):
        path = tmp_path / str(number)
        path.mkdir()
        values.append(str(path))
    config = CheckerConfig(allowed_roots=(tmp_path.resolve(),), targets={})

    with pytest.raises(ConfigurationError, match="between one and five"):
        select_paths(config, None, values, [])

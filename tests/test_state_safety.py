from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from enroll.state import StateSafetyError, load_state, open_state_file


def test_load_state_reads_regular_state_json(tmp_path: Path):
    (tmp_path / "state.json").write_text(
        json.dumps({"host": {"hostname": "test-host"}}), encoding="utf-8"
    )

    assert load_state(tmp_path)["host"]["hostname"] == "test-host"


def test_load_state_rejects_state_json_symlink(tmp_path: Path):
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    (tmp_path / "state.json").symlink_to(target)

    with pytest.raises(StateSafetyError, match="state.json is a symlink"):
        load_state(tmp_path)


def test_load_state_rejects_non_regular_state_json(tmp_path: Path):
    (tmp_path / "state.json").mkdir()

    with pytest.raises(StateSafetyError, match="state.json is not a regular file"):
        load_state(tmp_path)


def test_load_state_rejects_hardlinked_state_json(tmp_path: Path):
    state_file = tmp_path / "state.json"
    state_file.write_text("{}", encoding="utf-8")
    os.link(state_file, tmp_path / "state-copy.json")

    with pytest.raises(StateSafetyError, match="state.json is hardlinked"):
        load_state(tmp_path)


def test_open_state_file_rejects_oversized_state_json(tmp_path: Path):
    (tmp_path / "state.json").write_text("{}", encoding="utf-8")

    with pytest.raises(StateSafetyError, match="state.json is too large"):
        open_state_file(tmp_path, max_bytes=1)

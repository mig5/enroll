from __future__ import annotations

import os
import tarfile
from pathlib import Path

import pytest


def _make_bundle_dir(tmp_path: Path) -> Path:
    b = tmp_path / "bundle"
    (b / "artifacts").mkdir(parents=True)
    (b / "state.json").write_text("{}\n", encoding="utf-8")
    return b


def _tar_gz_of_dir(src: Path, out: Path) -> None:
    with tarfile.open(out, mode="w:gz") as tf:
        # tar -C src . semantics
        for p in src.rglob("*"):
            rel = p.relative_to(src)
            tf.add(p, arcname=str(rel))


def test_bundle_from_directory_and_statejson_path(tmp_path: Path):
    import enroll.diff as d

    b = _make_bundle_dir(tmp_path)

    br1 = d._bundle_from_input(str(b), sops_mode=False)
    assert br1.dir == b
    assert br1.state_path.exists()

    br2 = d._bundle_from_input(str(b / "state.json"), sops_mode=False)
    assert br2.dir == b


def test_bundle_from_tarball_extracts(tmp_path: Path):
    import enroll.diff as d

    b = _make_bundle_dir(tmp_path)
    tgz = tmp_path / "bundle.tgz"
    _tar_gz_of_dir(b, tgz)

    br = d._bundle_from_input(str(tgz), sops_mode=False)
    try:
        assert br.dir.is_dir()
        assert (br.dir / "state.json").exists()
    finally:
        if br.tempdir:
            br.tempdir.cleanup()


def test_bundle_from_sops_like_file(monkeypatch, tmp_path: Path):
    import enroll.diff as d

    b = _make_bundle_dir(tmp_path)
    tgz = tmp_path / "bundle.tar.gz"
    _tar_gz_of_dir(b, tgz)

    # Pretend the tarball is an encrypted bundle by giving it a .sops name.
    sops_path = tmp_path / "bundle.tar.gz.sops"
    sops_path.write_bytes(tgz.read_bytes())

    # Stub out sops machinery: "decrypt" just copies through.
    monkeypatch.setattr(d, "require_sops_cmd", lambda: "sops")

    def fake_decrypt(src: Path, dest: Path, mode: int):
        dest.write_bytes(Path(src).read_bytes())
        try:
            os.chmod(dest, mode)
        except OSError:
            pass

    monkeypatch.setattr(d, "decrypt_file_binary_to", fake_decrypt)

    br = d._bundle_from_input(str(sops_path), sops_mode=False)
    try:
        assert (br.dir / "state.json").exists()
    finally:
        if br.tempdir:
            br.tempdir.cleanup()


def test_bundle_from_input_missing_path(tmp_path: Path):
    import enroll.diff as d

    with pytest.raises(RuntimeError, match="not found"):
        d._bundle_from_input(str(tmp_path / "nope"), sops_mode=False)

from __future__ import annotations

import json
import re
import shutil
import subprocess  # nosec B404
from collections.abc import (
    Iterable,
)  # nosec - executes fixed docker/podman command arguments only
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..harvest_types import ContainerImagesSnapshot
from .context import HarvestCollector

_DIGEST_RE = re.compile(r"@sha256:[0-9A-Fa-f]{32,}")
_SHA_ID_RE = re.compile(r"^(?:sha256:)?[0-9A-Fa-f]{64}$")


def _normalise_image_id(value: Any) -> Optional[str]:
    s = str(value or "").strip()
    if not s:
        return None
    if s.startswith("sha256:"):
        return s
    if _SHA_ID_RE.match(s):
        return "sha256:" + s
    return s


def _as_string_list(value: Any) -> List[str]:
    if not value:
        return []
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, Iterable):
        values = list(value)
    else:
        values = [value]
    out: List[str] = []
    for item in values:
        s = str(item or "").strip()
        if not s or s in {"<none>", "<none>:<none>"}:
            continue
        if s not in out:
            out.append(s)
    return out


def _pullable_digests(value: Any) -> List[str]:
    return [s for s in _as_string_list(value) if _DIGEST_RE.search(s)]


def _split_tag_ref(ref: str) -> Optional[Dict[str, str]]:
    """Split an image tag into repository/tag, preserving registry ports."""

    s = str(ref or "").strip()
    if not s or "@" in s or s == "<none>:<none>":
        return None
    last_slash = s.rfind("/")
    last_colon = s.rfind(":")
    if last_colon > last_slash:
        repository = s[:last_colon]
        tag = s[last_colon + 1 :]
    else:
        repository = s
        tag = "latest"
    if not repository or not tag:
        return None
    return {"ref": s, "repository": repository, "tag": tag}


def _tag_aliases(value: Any) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    seen = set()
    for ref in _as_string_list(value):
        item = _split_tag_ref(ref)
        if not item:
            continue
        key = (item["repository"], item["tag"])
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _platform_from_inspect(
    item: Dict[str, Any],
) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    os_name = item.get("Os") or item.get("OS")
    arch = item.get("Architecture") or item.get("Arch")
    variant = item.get("Variant")
    os_s = str(os_name).strip() if os_name not in (None, "") else None
    arch_s = str(arch).strip() if arch not in (None, "") else None
    variant_s = str(variant).strip() if variant not in (None, "") else None
    platform = None
    if os_s and arch_s:
        platform = f"{os_s}/{arch_s}"
        if variant_s:
            platform = f"{platform}/{variant_s}"
    return os_s, arch_s, variant_s, platform


def _run_command(
    argv: Sequence[str], *, timeout: int = 20
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # nosec - argv is constructed from fixed binary names and image ids
        list(argv),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
    )


def _chunks(items: Sequence[str], size: int) -> Iterable[List[str]]:
    for i in range(0, len(items), size):
        yield list(items[i : i + size])


class ContainerImagesCollector(HarvestCollector):
    """Collect local Docker and Podman image metadata.

    The harvest records pullable registry digests where present. Local image IDs
    are kept as evidence but are not treated as pull references.
    """

    def collect(self) -> ContainerImagesSnapshot:
        images: List[Dict[str, Any]] = []
        notes: List[str] = []

        images.extend(self._collect_engine("docker", notes=notes))
        images.extend(self._collect_engine("podman", notes=notes))

        if images:
            digest_count = len([img for img in images if img.get("pull_ref")])
            notes.append(
                f"Detected {len(images)} container image(s); {digest_count} have registry digests usable for exact pulls."
            )

        return ContainerImagesSnapshot(
            role_name="container_images",
            images=images,
            notes=notes,
        )

    def _collect_engine(self, engine: str, *, notes: List[str]) -> List[Dict[str, Any]]:
        exe = shutil.which(engine)
        if not exe:
            return []

        try:
            listed = _run_command([exe, "image", "ls", "-q", "--no-trunc"])
        except Exception as exc:
            notes.append(f"Failed to list {engine} images: {exc!r}")
            return []

        if listed.returncode != 0:
            detail = (listed.stderr or listed.stdout or "").strip()
            if detail:
                notes.append(f"Failed to list {engine} images: {detail}")
            else:
                notes.append(
                    f"Failed to list {engine} images: exit {listed.returncode}"
                )
            return []

        image_ids = []
        seen_ids = set()
        for line in listed.stdout.splitlines():
            image_id = _normalise_image_id(line)
            if not image_id or image_id in seen_ids:
                continue
            seen_ids.add(image_id)
            image_ids.append(image_id)

        if not image_ids:
            return []

        out: List[Dict[str, Any]] = []
        for chunk in _chunks(image_ids, 40):
            try:
                inspected = _run_command([exe, "image", "inspect", *chunk])
            except Exception as exc:
                notes.append(f"Failed to inspect {engine} images: {exc!r}")
                continue
            if inspected.returncode != 0:
                detail = (inspected.stderr or inspected.stdout or "").strip()
                notes.append(
                    f"Failed to inspect {engine} images {', '.join(chunk[:3])}: {detail or inspected.returncode}"
                )
                continue
            try:
                data = json.loads(inspected.stdout or "[]")
            except json.JSONDecodeError as exc:
                notes.append(f"Failed to parse {engine} image inspect JSON: {exc}")
                continue
            if not isinstance(data, list):
                notes.append(f"Unexpected {engine} image inspect JSON shape")
                continue
            for item in data:
                if isinstance(item, dict):
                    normalised = self._normalise_inspect(engine, item)
                    if normalised is not None:
                        out.append(normalised)
        return out

    def _normalise_inspect(
        self, engine: str, item: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        image_id = _normalise_image_id(item.get("Id") or item.get("ID"))
        repo_tags = _as_string_list(item.get("RepoTags"))
        repo_digests = _pullable_digests(item.get("RepoDigests"))
        pull_ref = sorted(repo_digests)[0] if repo_digests else None
        os_name, arch, variant, platform = _platform_from_inspect(item)

        if not image_id and not repo_tags and not repo_digests:
            return None

        notes: List[str] = []
        if not pull_ref:
            if repo_tags:
                notes.append(
                    "Image has tag(s) but no RepoDigest; exact digest-pinned pull cannot be rendered."
                )
            else:
                notes.append(
                    "Image has no tag or RepoDigest; local-only/dangling images cannot be pulled from a registry."
                )

        out: Dict[str, Any] = {
            "engine": engine,
            "scope": "system",
            "user": None,
            "home": None,
            "image_id": image_id,
            "repo_tags": repo_tags,
            "repo_digests": repo_digests,
            "pull_ref": pull_ref,
            "tag_aliases": _tag_aliases(repo_tags),
            "os": os_name,
            "architecture": arch,
            "variant": variant,
            "platform": platform,
            "size": item.get("Size"),
            "created": item.get("Created"),
            "source": f"{engine} image inspect",
            "notes": notes,
        }
        return out

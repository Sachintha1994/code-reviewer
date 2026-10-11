"""Safe extraction of uploaded ZIP files.

Guards against path traversal ("zip slip"), absolute paths, symlinks, too many
files and zip bombs before anything is written to disk.
"""
from __future__ import annotations

import os
import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Dict, Optional

from app.core.files import long_path

DEFAULT_LIMITS = {"max_zip_mb": 200, "max_unzipped_mb": 1000, "max_files": 50000}


class UploadError(ValueError):
    pass


def limits(cfg: Dict[str, Any]) -> Dict[str, int]:
    out = dict(DEFAULT_LIMITS)
    out.update({k: int(v) for k, v in (cfg.get("uploads") or {}).items() if k in DEFAULT_LIMITS})
    return out


def _safe_member_path(name: str) -> PurePosixPath | None:
    """Relative path inside the archive, or None for entries to skip. Raises on unsafe paths."""
    name = name.replace("\\", "/")
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        raise UploadError(f"the ZIP contains an absolute path ({name}); refusing to extract it")
    parts = [p for p in PurePosixPath(name).parts if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise UploadError(f"the ZIP contains a path that escapes its folder ({name}); refusing to extract it")
    if not parts or parts[0] == "__MACOSX":
        return None
    return PurePosixPath(*parts)


def extract_zip(zip_path: Path, dest: Path, cfg: Dict[str, Any],
                keep: Optional[Callable[[str], bool]] = None) -> Path:
    """Extract into dest and return the project root (the single top folder, if there is one).

    `keep(relative_path)` decides which files are written; the rest (build output,
    binaries, dependencies) are skipped, which keeps uploads fast and paths short."""
    lim = limits(cfg)
    try:
        archive = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as exc:
        raise UploadError("that file isn't a valid ZIP archive") from exc
    with archive:
        entries = []
        total = 0
        for info in archive.infolist():
            rel = _safe_member_path(info.filename)
            if rel is None or info.is_dir():
                continue
            if stat.S_ISLNK(info.external_attr >> 16):
                continue  # never follow or create symlinks from an upload
            if keep is not None and not keep(rel.as_posix()):
                continue
            total += info.file_size
            entries.append((info, rel))
            if len(entries) > lim["max_files"]:
                raise UploadError(f"the ZIP has more than {lim['max_files']} files")
            if total > lim["max_unzipped_mb"] * 1024 * 1024:
                raise UploadError(f"the ZIP unpacks to more than {lim['max_unzipped_mb']} MB")
        if not entries:
            raise UploadError("the ZIP has no source files to review" if keep else "the ZIP is empty")

        if dest.exists():
            shutil.rmtree(long_path(dest))
        os.makedirs(long_path(dest))
        root = dest.resolve()
        written = 0
        budget = lim["max_unzipped_mb"] * 1024 * 1024
        for info, rel in entries:
            target = (root / rel).resolve()
            if root not in target.parents:
                raise UploadError(f"unsafe path in ZIP: {info.filename}")
            os.makedirs(long_path(target.parent), exist_ok=True)
            with archive.open(info) as src, open(long_path(target), "wb") as out:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)
                    if written > budget:  # sizes in the ZIP header can lie
                        raise UploadError(f"the ZIP unpacks to more than {lim['max_unzipped_mb']} MB")
                    out.write(chunk)

    children = [p for p in root.iterdir()]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return root

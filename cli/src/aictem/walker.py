"""File discovery: walk a tree, skipping build output, dependencies and anything in .aictemignore."""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterator
from pathlib import Path

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", ".nox", "dist", "build", ".next", ".nuxt", ".turbo", ".cache", "target", "vendor", ".terraform",
    "site-packages", "coverage", ".gradle", ".idea", "bower_components", ".parcel-cache", ".svelte-kit", ".output",
}
MAX_TEXT_BYTES = 2 * 1024 * 1024


class Walker:
    def __init__(self, root: Path, *, max_files: int = 50_000, extra_ignores: list[str] | None = None) -> None:
        self.root = root.resolve()
        self.max_files = max_files
        self.ignores = list(extra_ignores or [])
        ignore_file = self.root / ".aictemignore"
        if ignore_file.is_file():
            self.ignores += [line.strip() for line in ignore_file.read_text(errors="replace").splitlines()
                             if line.strip() and not line.startswith("#")]
        self.files_seen = 0
        self.truncated = False

    def ignored(self, rel: str) -> bool:
        return any(fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(rel, pattern.rstrip("/") + "/*") for pattern in self.ignores)

    def __iter__(self) -> Iterator[tuple[Path, str]]:
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            rel_dir = os.path.relpath(dirpath, self.root)
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not self.ignored(os.path.normpath(os.path.join(rel_dir, d)))
                                 and not os.path.isfile(os.path.join(dirpath, d, "pyvenv.cfg")))  # any Python virtual environment
            for name in sorted(filenames):
                path = Path(dirpath) / name
                rel = path.relative_to(self.root).as_posix()
                if path.is_symlink() or self.ignored(rel):
                    continue
                self.files_seen += 1
                if self.files_seen > self.max_files:
                    self.truncated = True
                    return
                yield path, rel


GENERATED = (".min.js", ".min.css", ".bundle.js", ".map", ".snap")


def read_text(path: Path) -> str | None:
    """Text content of a file, or None for binary or oversized files."""
    if path.name.endswith(GENERATED):
        return None
    try:
        if path.stat().st_size > MAX_TEXT_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")

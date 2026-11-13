"""Repository identity from git metadata, read directly from .git so git need not be installed."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path


def normalise_remote(url: str) -> str:
    """git@github.com:org/repo.git, https://user@github.com/org/repo -> github.com/org/repo"""
    url = url.strip()
    m = re.match(r"^[\w.-]+@([\w.-]+):(.+)$", url)  # scp-like ssh syntax
    if m:
        host, path = m.groups()
    else:
        m = re.match(r"^[a-z+]+://(?:[^@/]+@)?([^/:]+)(?::\d+)?/(.+)$", url)
        if not m:
            return url
        host, path = m.groups()
    path = re.sub(r"\.git/?$", "", path.strip("/"))
    return f"{host.lower()}/{path}"


def safe_remote(url: str) -> str:
    """The remote without any user name, password or token (https://user:token@host/... -> https://host/...)."""
    return re.sub(r"^([a-z+]+://)[^@/]+@", r"\1", url.strip())


def _origin_url(config_text: str) -> str | None:
    """url of [remote "origin"]. Parsed by hand: git config allows value-less keys and repeats that ini parsers reject."""
    section = None
    for raw in config_text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            section = re.sub(r"\s+", " ", line.strip("[]")).lower()
        elif section == 'remote "origin"':
            m = re.match(r"url\s*=\s*(.+)$", line)
            if m:
                return m.group(1).strip().strip('"')
    return None


def _git_dir(root: Path) -> Path | None:
    for candidate in (root, *root.parents):
        dotgit = candidate / ".git"
        if dotgit.is_dir():
            return dotgit
        if dotgit.is_file():  # worktree or submodule: "gitdir: <path>"
            text = dotgit.read_text(errors="replace").strip()
            if text.startswith("gitdir:"):
                return (candidate / text.split(":", 1)[1].strip()).resolve()
    return None


def info(root: Path) -> dict:
    """{identifier, name, remote, branch, commit, root}; identifier falls back to the absolute path."""
    root = root.resolve()
    result: dict = {"root": str(root), "name": root.name, "identifier": str(root), "remote": None, "branch": None, "commit": None}
    git_dir = _git_dir(root)
    if git_dir is None:
        return result
    common = git_dir
    if (git_dir / "commondir").is_file():
        common = (git_dir / (git_dir / "commondir").read_text().strip()).resolve()
    try:
        remote = _origin_url((common / "config").read_text(errors="replace"))
    except OSError:
        remote = None
    if remote:
        result["remote"] = safe_remote(remote)
        result["identifier"] = normalise_remote(remote)
        result["name"] = result["identifier"].rsplit("/", 1)[-1]
    head_file = git_dir / "HEAD"
    head = head_file.read_text().strip() if head_file.is_file() else ""
    if head.startswith("ref:"):
        ref = head.split(":", 1)[1].strip()
        result["branch"] = ref.removeprefix("refs/heads/")
        ref_file = common / ref
        if ref_file.is_file():
            result["commit"] = ref_file.read_text().strip()
        elif (common / "packed-refs").is_file():
            for line in (common / "packed-refs").read_text().splitlines():
                if line.endswith(" " + ref):
                    result["commit"] = line.split(" ", 1)[0]
    elif re.fullmatch(r"[0-9a-f]{40}", head):
        result["commit"] = head
    # CI systems check out detached heads; their environment names the branch.
    for var in ("GITHUB_HEAD_REF", "GITHUB_REF_NAME", "CI_COMMIT_REF_NAME", "BRANCH_NAME", "BUILD_SOURCEBRANCHNAME"):
        if os.environ.get(var) and not result["branch"]:
            result["branch"] = os.environ[var]
    return result


def tracked_files(root: Path) -> set[str] | None:
    """Paths git tracks, when git is available; used to mark untracked secrets as lower confidence."""
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, timeout=20, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return {p for p in out.decode(errors="replace").split("\0") if p}

"""Scanning must never run anything the scanned repository supplies."""

import shutil
import subprocess

import pytest

from aictem import gitinfo, scan


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git")
def test_scanning_does_not_run_programs_named_in_the_repository_git_config(tmp_path):
    repo, marker = tmp_path / "repo", tmp_path / "EXECUTED"
    repo.mkdir()
    hook = tmp_path / "hook.sh"
    hook.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
    hook.chmod(0o755)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    for key in ("core.fsmonitor", "core.pager", "core.sshCommand"):
        subprocess.run(["git", "-C", str(repo), "config", key, str(hook)], check=True)
    (repo / "app.py").write_text("import openai\n")
    subprocess.run(["git", "-C", str(repo), "add", "app.py"], check=True)
    marker.unlink(missing_ok=True)  # `git add` itself runs the monitor; only the scan is under test

    assert gitinfo.tracked_files(repo) == {"app.py"}
    report = scan.run(repo)
    assert any(a["type"] == "ai_provider" for a in report["assets"])
    assert not marker.exists(), "a program named in the scanned repository's git config was executed"

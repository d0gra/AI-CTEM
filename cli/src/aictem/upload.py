"""Send a report to the CTEM platform through its CI ingestion endpoint (upload-only pipeline token)."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

from aictem import __version__

CI_PROVIDERS = (("GITHUB_ACTIONS", "github_actions"), ("GITLAB_CI", "gitlab_ci"), ("JENKINS_URL", "jenkins"), ("TF_BUILD", "azure_pipelines"),
                ("CIRCLECI", "circleci"), ("BITBUCKET_BUILD_NUMBER", "bitbucket"))


def pipeline_url() -> str | None:
    env = os.environ
    if env.get("GITHUB_RUN_ID") and env.get("GITHUB_REPOSITORY"):
        return f"{env.get('GITHUB_SERVER_URL', 'https://github.com')}/{env['GITHUB_REPOSITORY']}/actions/runs/{env['GITHUB_RUN_ID']}"
    return env.get("CI_PIPELINE_URL") or env.get("BUILD_URL") or env.get("CIRCLE_BUILD_URL")


def send(report: dict, url: str, token: str, *, fail_on: str = "none", wait: bool = True, timeout: float = 180) -> tuple[int, dict]:
    """Returns (HTTP status, response body). 412 means the server-side gate failed."""
    target = report["target"]
    provider = next((name for var, name in CI_PROVIDERS if os.environ.get(var)), "cli")
    query = {k: v for k, v in {"format": "ctem", "repository": target.get("repository"), "branch": target.get("branch"),
                               "commit": target.get("commit"), "provider": provider, "pipeline_url": pipeline_url(),
                               "fail_on": fail_on, "exit_code": "true", "wait": "true" if wait else "false"}.items() if v}
    endpoint = url.rstrip("/") + "/api/v1/ci/ingest?" + urllib.parse.urlencode(query)
    parts = urllib.parse.urlsplit(endpoint)
    if parts.scheme != "https" and not (parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1", "::1")):
        raise SystemExit("aictem: refusing to send a token over plain HTTP to a non-local address; use https://")
    request = urllib.request.Request(endpoint, data=json.dumps(report).encode(), method="POST", headers={
        "Authorization": f"Bearer {token}", "Content-Type": "application/json", "User-Agent": f"aictem/{__version__}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read() or b"{}")
        except ValueError:
            body = {"error": {"message": exc.reason}}
        return exc.code, body
    except urllib.error.URLError as exc:
        raise SystemExit(f"aictem: could not reach {url}: {exc.reason}") from exc

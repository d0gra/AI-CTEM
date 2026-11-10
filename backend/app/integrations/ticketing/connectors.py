"""Ticketing connectors: GitHub Issues, GitLab Issues and Jira Cloud."""

import base64
from dataclasses import dataclass
from urllib.parse import quote

import httpx
from pydantic import BaseModel, Field, HttpUrl

from app.integrations.base import ConnectionResult, ConnectorSpec, HttpApi, register_connector, run_test


@dataclass
class Ticket:
    system: str
    key: str
    url: str


class GitHubConfig(BaseModel):
    repository: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", description="owner/name")
    api_url: HttpUrl = HttpUrl("https://api.github.com")
    labels: list[str] = ["security"]


class TokenCredentials(BaseModel):
    token: str = Field(min_length=8)


class GitLabConfig(BaseModel):
    project: str = Field(min_length=1, description="Numeric id or namespace/project path")
    api_url: HttpUrl = HttpUrl("https://gitlab.com/api/v4")
    labels: list[str] = ["security"]


class JiraConfig(BaseModel):
    base_url: HttpUrl = Field(description="https://<site>.atlassian.net")
    project_key: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,19}$")
    issue_type: str = "Task"


class JiraCredentials(BaseModel):
    email: str
    api_token: str = Field(min_length=8)


def _github(config: GitHubConfig, creds: TokenCredentials, transport: httpx.BaseTransport | None = None) -> HttpApi:
    return HttpApi(str(config.api_url), {"Authorization": f"Bearer {creds.token}", "X-GitHub-Api-Version": "2022-11-28",
                                         "Accept": "application/vnd.github+json"}, transport=transport)


def _gitlab(config: GitLabConfig, creds: TokenCredentials, transport: httpx.BaseTransport | None = None) -> HttpApi:
    return HttpApi(str(config.api_url), {"PRIVATE-TOKEN": creds.token}, transport=transport)


def _jira(config: JiraConfig, creds: JiraCredentials, transport: httpx.BaseTransport | None = None) -> HttpApi:
    basic = base64.b64encode(f"{creds.email}:{creds.api_token}".encode()).decode()
    return HttpApi(str(config.base_url), {"Authorization": f"Basic {basic}"}, transport=transport)


def test_github(config: GitHubConfig, creds: TokenCredentials, transport=None) -> ConnectionResult:
    def go() -> ConnectionResult:
        repo = _github(config, creds, transport).get_json(f"/repos/{config.repository}")
        if not repo.get("has_issues", True):
            return ConnectionResult(False, "Issues are disabled for this repository", "config")
        return ConnectionResult(True, f"Connected to {repo.get('full_name')}", metadata={"private": repo.get("private")})

    return run_test(go)


def test_gitlab(config: GitLabConfig, creds: TokenCredentials, transport=None) -> ConnectionResult:
    def go() -> ConnectionResult:
        project = _gitlab(config, creds, transport).get_json(f"/projects/{quote(config.project, safe='')}")
        return ConnectionResult(True, f"Connected to {project.get('path_with_namespace')}")

    return run_test(go)


def test_jira(config: JiraConfig, creds: JiraCredentials, transport=None) -> ConnectionResult:
    def go() -> ConnectionResult:
        api = _jira(config, creds, transport)
        me = api.get_json("/rest/api/3/myself")
        project = api.get_json(f"/rest/api/3/project/{config.project_key}")
        return ConnectionResult(True, f"Connected as {me.get('displayName')} to project {project.get('name')}")

    return run_test(go)


def create_ticket(connector: str, config: dict, credentials: dict, *, title: str, body: str,
                  transport: httpx.BaseTransport | None = None) -> Ticket:
    """Create one ticket. Raises ApiError with a classified error on failure."""
    if connector == "github_issues":
        gh_config, gh_creds = GitHubConfig.model_validate(config), TokenCredentials.model_validate(credentials)
        issue = _github(gh_config, gh_creds, transport).request(
            "POST", f"/repos/{gh_config.repository}/issues",
            json_body={"title": title[:250], "body": body, "labels": gh_config.labels}).json()
        return Ticket("github_issues", f"#{issue['number']}", issue["html_url"])
    if connector == "gitlab_issues":
        gl_config, gl_creds = GitLabConfig.model_validate(config), TokenCredentials.model_validate(credentials)
        issue = _gitlab(gl_config, gl_creds, transport).request(
            "POST", f"/projects/{quote(gl_config.project, safe='')}/issues",
            json_body={"title": title[:250], "description": body, "labels": ",".join(gl_config.labels)}).json()
        return Ticket("gitlab_issues", f"#{issue['iid']}", issue["web_url"])
    if connector == "jira":
        j_config, j_creds = JiraConfig.model_validate(config), JiraCredentials.model_validate(credentials)
        doc = {"type": "doc", "version": 1, "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": para[:30000]}]}
            for para in body.split("\n\n") if para.strip()]}
        issue = _jira(j_config, j_creds, transport).request("POST", "/rest/api/3/issue", json_body={"fields": {
            "project": {"key": j_config.project_key}, "summary": title[:250], "issuetype": {"name": j_config.issue_type},
            "description": doc}}).json()
        return Ticket("jira", issue["key"], f"{str(j_config.base_url).rstrip('/')}/browse/{issue['key']}")
    raise ValueError(f"{connector} is not a ticketing connector")


TICKETING = ("github_issues", "gitlab_issues", "jira")

register_connector(ConnectorSpec(
    key="github_issues", name="GitHub Issues", category="ticketing", config_model=GitHubConfig,
    credentials_model=TokenCredentials, test=test_github,
    description="Creates issues for remediation tasks in a GitHub repository.",
    required_permissions="Fine-grained token with Issues: read and write on the target repository.",
))
register_connector(ConnectorSpec(
    key="gitlab_issues", name="GitLab Issues", category="ticketing", config_model=GitLabConfig,
    credentials_model=TokenCredentials, test=test_gitlab,
    description="Creates issues for remediation tasks in a GitLab project.",
    required_permissions="Project access token with the api scope and Reporter role.",
))
register_connector(ConnectorSpec(
    key="jira", name="Jira Cloud", category="ticketing", config_model=JiraConfig, credentials_model=JiraCredentials,
    test=test_jira, description="Creates issues for remediation tasks in a Jira Cloud project.",
    required_permissions="API token for a user with Create Issues permission in the project.",
))

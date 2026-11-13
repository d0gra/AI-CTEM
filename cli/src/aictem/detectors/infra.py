"""Containers (Dockerfile, Compose, Kubernetes), infrastructure as code (Terraform, CloudFormation) and CI pipelines."""

from __future__ import annotations

import re

from aictem.catalog import CFN_TYPES, IMAGE_INDEX, TERRAFORM_TYPES, resource_type
from aictem.detectors import Context, line_of
from aictem.model import Finding, Location

FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.IGNORECASE | re.MULTILINE)
YAML_IMAGE = re.compile(r"^\s*-?\s*image:\s*['\"]?([^\s'\"#]+)", re.MULTILINE)
SHA_PIN = re.compile(r"@sha256:[0-9a-f]{64}$")


def _image_asset(ctx: Context, image: str, rel: str, line: int, how: str):
    image = image.strip()
    if not image or image.lower() == "scratch" or "$" in image or "{{" in image:
        return None
    name = image.split("@", 1)[0]
    tag = name.rsplit(":", 1)[1] if ":" in name.rsplit("/", 1)[-1] else None
    asset = ctx.inventory.add("container_image", image, image, attributes={"tag": tag, "digest_pinned": bool(SHA_PIN.search(image)),
                                                                           "referenced_in": [rel], "reference": how},
                              location=Location(rel, line, "container"))
    ctx.inventory.link(ctx.repo, asset, "DEPENDS_ON", via=rel)
    bare = name.rsplit(":", 1)[0] if tag else name
    tech = next((t for prefix, t in IMAGE_INDEX.items() if bare == prefix or bare.startswith(prefix)), None)
    if tech:
        ctx.signal(tech.key, "container", rel, line)
        asset.attributes.setdefault("ai_technology", tech.name)
    return asset


def dockerfile(ctx: Context, rel: str, text: str) -> None:
    stages: set[str] = set()
    for m in FROM.finditer(text):
        image, alias = m.group(1), m.group(2)
        if image.lower() not in stages:
            asset = _image_asset(ctx, image, rel, line_of(text, m.start()), "base image")
            if asset and asset.attributes.get("tag") in (None, "latest") and not asset.attributes["digest_pinned"]:
                ctx.inventory.finding(Finding(
                    rule_id="container.base_image.unpinned", title=f"Base image {image} is not pinned to a version ({rel})", severity="low",
                    domain="container", asset=ctx.repo.ref, file=rel, line=line_of(text, m.start()), confidence="confirmed", cwe="CWE-1104",
                    description="Builds pull whatever the tag points to at build time, so images change without review.",
                    remediation="Pin a version tag, ideally with a digest (image:tag@sha256:...).", discriminator=f"{rel}:{image}"))
        if alias:
            stages.add(alias.lower())
    froms = list(FROM.finditer(text))
    final = text[froms[-1].start():] if froms else ""  # only the last stage ships
    users = re.findall(r"^\s*USER\s+(\S+)", final, re.IGNORECASE | re.MULTILINE)
    base_is_nonroot = bool(froms) and re.search(r"nonroot|distroless.*:nonroot|chainguard|bitnami/", froms[-1].group(1)) is not None
    drops_privileges = re.search(r"\b(gosu|su-exec|setpriv|runuser)\b", text) is not None  # entrypoint switches user at start
    if froms and not base_is_nonroot and (not users or users[-1] in ("root", "0", "0:0")):
        ctx.inventory.finding(Finding(
            rule_id="container.runs_as_root", title=f"Container image runs as root ({rel})", severity="low", domain="container", asset=ctx.repo.ref,
            file=rel, confidence="tentative" if drops_privileges or not users else "firm", cwe="CWE-250",
            description="No USER instruction switches to an unprivileged user in the final stage"
                        + (", though the image installs a tool for dropping privileges at start-up (check the entrypoint)." if drops_privileges
                           else ". The base image may already set one; check with `docker inspect`."),
            remediation="Create an unprivileged user and add `USER <name>` before the entrypoint.", discriminator=rel))


def compose_or_k8s(ctx: Context, rel: str, text: str) -> None:
    for m in YAML_IMAGE.finditer(text):
        asset = _image_asset(ctx, m.group(1), rel, line_of(text, m.start()), "kubernetes" if "kind:" in text else "compose")
        if asset and asset.attributes.get("tag") in (None, "latest") and not asset.attributes["digest_pinned"]:
            ctx.inventory.finding(Finding(
                rule_id="container.image.unpinned", title=f"Image {m.group(1)} is not pinned to a version ({rel})", severity="low",
                domain="container", asset=ctx.repo.ref, file=rel, line=line_of(text, m.start()), confidence="confirmed", cwe="CWE-1104",
                description="Deployments pull whatever the tag points to at the time, so the running software changes without review.",
                remediation="Pin a version tag, ideally with a digest (image:tag@sha256:...).", discriminator=f"{rel}:{m.group(1)}"))
    if "kind:" in text and "apiVersion:" in text:
        for m in re.finditer(r"^kind:\s*(\w+)\s*$[\s\S]*?^\s+name:\s*['\"]?([\w.\-]+)", text, re.MULTILINE):
            kind, name = m.groups()
            if kind in ("Deployment", "StatefulSet", "DaemonSet", "Service", "Ingress", "CronJob", "Job", "Pod"):
                asset = ctx.inventory.add("k8s_resource", f"k8s:{ctx.repo.identifier}:{kind}/{name}", f"{kind} {name}",
                                          attributes={"kind": kind, "manifest": rel}, location=Location(rel, line_of(text, m.start()), "iac"))
                ctx.inventory.link(ctx.repo, asset, "CONTAINS", via=rel)
        for m in re.finditer(r"^\s*privileged:\s*true", text, re.MULTILINE):
            ctx.inventory.finding(Finding(
                rule_id="container.privileged", title=f"Privileged container in {rel}", severity="high", domain="container", asset=ctx.repo.ref,
                file=rel, line=line_of(text, m.start()), confidence="confirmed", cwe="CWE-250",
                description="A privileged container has full access to the host's devices and kernel features.",
                remediation="Remove privileged mode and grant only the specific capabilities required.", discriminator=f"{rel}:{line_of(text, m.start())}"))
    elif re.search(r"^services:\s*$", text, re.MULTILINE):
        for m in re.finditer(r"^\s*privileged:\s*true", text, re.MULTILINE):
            ctx.inventory.finding(Finding(
                rule_id="container.privileged", title=f"Privileged container in {rel}", severity="high", domain="container", asset=ctx.repo.ref,
                file=rel, line=line_of(text, m.start()), confidence="confirmed", cwe="CWE-250",
                description="A privileged container has full access to the host's devices and kernel features.",
                remediation="Remove `privileged: true` and grant only the capabilities required.", discriminator=f"{rel}:{line_of(text, m.start())}"))


def _cloud_asset(ctx: Context, kind: str, address: str, rel: str, line: int, table, provider: str):
    match = resource_type(kind, table)
    if match is None:
        return None
    asset_type, tech_key = match
    # The same address (aws_s3_bucket.docs) in envs/dev and envs/prod is two resources, so the directory is part of the identity.
    directory = rel.rsplit("/", 1)[0] if "/" in rel else ""
    scoped = f"{directory}/{address}" if directory else address
    is_ai = asset_type in ("llm_endpoint", "ai_model", "ai_agent", "rag_application", "ai_provider", "vector_database", "model_registry")
    asset = ctx.inventory.add(asset_type, f"{provider}:{ctx.repo.identifier}:{scoped}", scoped,
                              attributes={"resource_type": kind, "defined_in": rel, "iac": provider, "ai_technology": tech_key},
                              ai={"provider": tech_key, "managed": True} if is_ai else None, location=Location(rel, line, "iac"))
    ctx.inventory.link(ctx.repo, asset, "CONTAINS", via=rel)
    if tech_key:
        ctx.signal(tech_key, "iac", rel, line)
    return asset


def terraform(ctx: Context, rel: str, text: str) -> None:
    for m in re.finditer(r'^\s*resource\s+"([\w-]+)"\s+"([\w-]+)"\s*\{', text, re.MULTILINE):
        kind, name = m.groups()
        line = line_of(text, m.start())
        asset = _cloud_asset(ctx, kind, f"{kind}.{name}", rel, line, TERRAFORM_TYPES, "terraform")
        body = re.split(r"\n(?:resource|data|module|variable|output|locals|provider)\b", text[m.end():m.end() + 4000], maxsplit=1)[0]
        if kind in ("aws_s3_bucket", "aws_s3_bucket_acl") and re.search(r'\bacl\s*=\s*"public-read(?:-write)?"', body):
            ctx.inventory.finding(Finding(
                rule_id="iac.storage.public_acl", title=f"Bucket {kind}.{name} grants public access ({rel})", severity="high", domain="iac",
                asset=(asset or ctx.repo).ref, file=rel, line=line, confidence="confirmed", cwe="CWE-284", discriminator=f"{rel}:{kind}.{name}",
                description="The bucket ACL makes objects readable by anyone on the internet.", remediation="Remove the public ACL and enable block public access."))
        if asset and re.search(r"\bpublicly_accessible\s*=\s*true", body):
            ctx.inventory.finding(Finding(
                rule_id="iac.database.public", title=f"Database {kind}.{name} is publicly accessible ({rel})", severity="high", domain="iac",
                asset=asset.ref, file=rel, line=line, confidence="confirmed", cwe="CWE-284",
                description="The database gets a public address and accepts connections from outside the VPC.",
                remediation="Set publicly_accessible = false and reach it through private networking."))
    for m in re.finditer(r'^\s*provider\s+"([\w-]+)"', text, re.MULTILINE):
        ctx.repo.attributes.setdefault("terraform_providers", [])
        if m.group(1) not in ctx.repo.attributes["terraform_providers"]:
            ctx.repo.attributes["terraform_providers"].append(m.group(1))


def cloudformation(ctx: Context, rel: str, text: str) -> None:
    for m in re.finditer(r'(?:^\s{2}(\w+):\s*\n\s+Type:\s*["\']?(AWS::[\w:]+))|(?:"(\w+)"\s*:\s*\{\s*"Type"\s*:\s*"(AWS::[\w:]+)")', text, re.MULTILINE):
        name, kind = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
        _cloud_asset(ctx, kind, f"{kind}/{name}", rel, line_of(text, m.start()), CFN_TYPES, "cloudformation")


def github_workflow(ctx: Context, rel: str, text: str) -> None:
    ctx.ci_systems.add("GitHub Actions")
    for m in re.finditer(r"^\s*-?\s*uses:\s*['\"]?([\w.\-]+/[\w.\-/]+)@([\w.\-]+)", text, re.MULTILINE):
        action, ref = m.groups()
        if action.startswith(("actions/", "github/")) or re.fullmatch(r"[0-9a-f]{40}", ref):
            continue
        ctx.inventory.finding(Finding(
            rule_id="ci.actions.unpinned", title=f"Third-party action {action}@{ref} is not pinned to a commit ({rel})", severity="low",
            domain="supply_chain", asset=ctx.repo.ref, file=rel, line=line_of(text, m.start()), confidence="confirmed", cwe="CWE-829",
            description="A tag can be moved to different code; a compromised action then runs with the workflow's token and secrets.",
            remediation="Pin the action to a full commit SHA and note the version in a comment.", discriminator=f"{rel}:{action}"))
    if re.search(r"^\s*pull_request_target\s*:", text, re.MULTILINE) and re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)", text):
        ctx.inventory.finding(Finding(
            rule_id="ci.actions.pwn_request", title=f"Workflow checks out pull-request code under pull_request_target ({rel})", severity="high",
            domain="supply_chain", asset=ctx.repo.ref, file=rel, confidence="firm", cwe="CWE-94",
            description="pull_request_target runs with repository secrets and a write token; checking out the contributor's code lets a pull "
                        "request from a fork run code with those privileges.",
            remediation="Use the pull_request trigger for untrusted code, or never check out or build the head ref in pull_request_target jobs.",
            discriminator=rel))
    for m in UNTRUSTED_EXPR.finditer(text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        prefix = text[line_start:m.start()]
        # `NAME: ${{ ... }}` passes the value as data (an env or with entry); anything else interpolates it into a script.
        if re.fullmatch(r"\s*-?\s*[\w.-]+:\s*[\"']?", prefix) and not re.match(r"\s*-?\s*run:", prefix):
            continue
        line = line_of(text, m.start())
        ctx.inventory.finding(Finding(
            rule_id="ci.actions.script_injection", title=f"Workflow interpolates attacker-controlled text into a script ({rel})", severity="high",
            domain="supply_chain", asset=ctx.repo.ref, file=rel, line=line, confidence="firm", cwe="CWE-94",
            description=f"`{m.group(0)}` is replaced before the shell runs, so a crafted title, branch name or comment becomes shell commands "
                        "with the workflow's token and secrets.",
            remediation="Pass the value through an environment variable (env: TITLE: ${{ ... }}) and use \"$TITLE\" in the script.",
            discriminator=f"{rel}:{line}", evidence={"expression": m.group(0)}))
    if re.search(r"^\s*permissions:\s*write-all", text, re.MULTILINE):
        ctx.inventory.finding(Finding(
            rule_id="ci.actions.write_all", title=f"Workflow grants every permission to its token ({rel})", severity="medium", domain="supply_chain",
            asset=ctx.repo.ref, file=rel, confidence="confirmed", cwe="CWE-250",
            description="permissions: write-all gives each job a token that can push code, publish packages and change settings.",
            remediation="Declare only the permissions each job needs (for example `contents: read`).", discriminator=rel))


UNTRUSTED_EXPR = re.compile(r"\$\{\{\s*github\.(?:event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label)|"
                            r"comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|head_commit\.message|"
                            r"commits\[\d*\]?\.?message|pages\[[^\]]*\]\.page_name)|head_ref)\s*\}\}")
CI_FILES = {".gitlab-ci.yml": "GitLab CI", "Jenkinsfile": "Jenkins", "azure-pipelines.yml": "Azure Pipelines", "bitbucket-pipelines.yml": "Bitbucket Pipelines",
            ".travis.yml": "Travis CI", "cloudbuild.yaml": "Google Cloud Build", "buildspec.yml": "AWS CodeBuild"}


def classify(rel: str, text: str):
    """The infrastructure handler for a file, or None."""
    name = rel.rsplit("/", 1)[-1]
    lower = name.lower()
    if lower == "dockerfile" or lower.startswith("dockerfile.") or lower.endswith(".dockerfile") or lower == "containerfile":
        return dockerfile
    if rel.startswith(".github/workflows/") and lower.endswith((".yml", ".yaml")):
        return github_workflow
    if lower.endswith(".tf"):
        return terraform
    if lower.endswith((".yml", ".yaml", ".json", ".template")) and "AWSTemplateFormatVersion" in text[:4000]:
        return cloudformation
    if lower.endswith((".yml", ".yaml")) and (re.search(r"^services:\s*$", text, re.MULTILINE) or ("apiVersion:" in text and "kind:" in text)):
        return compose_or_k8s
    if name in CI_FILES or rel.startswith(".circleci/"):
        ctx_name = CI_FILES.get(name, "CircleCI")
        return lambda ctx, _rel, _text: ctx.ci_systems.add(ctx_name)
    return None

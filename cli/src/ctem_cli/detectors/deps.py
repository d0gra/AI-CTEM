"""Dependency manifests and lockfiles across ecosystems -> package assets and AI usage signals."""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from urllib.parse import quote

from ctem_cli.catalog import GO_INDEX, INTEGRATIONS, NPM_INDEX, PYPI_INDEX
from ctem_cli.detectors import Context
from ctem_cli.model import Location

PURL_TYPE = {"PyPI": "pypi", "npm": "npm", "Go": "golang", "crates.io": "cargo", "RubyGems": "gem", "Maven": "maven",
             "NuGet": "nuget", "Packagist": "composer"}
LOCKFILES = {"poetry.lock", "uv.lock", "Pipfile.lock", "package-lock.json", "npm-shrinkwrap.json", "Cargo.lock", "Gemfile.lock",
             "composer.lock", "go.sum", "pnpm-lock.yaml", "yarn.lock"}
_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*(==|===|~=|>=|<=|!=|>|<)?\s*([0-9][^\s;,#]*)?")


def pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def purl(ecosystem: str, name: str, version: str | None) -> str:
    kind = PURL_TYPE.get(ecosystem, "generic")
    if kind == "npm" and name.startswith("@"):
        scope, _, rest = name.partition("/")
        path = f"{quote(scope)}/{rest}"
    elif kind == "maven" and ":" in name:
        path = name.replace(":", "/", 1)
    else:
        path = name
    return f"pkg:{kind}/{path}" + (f"@{version}" if version else "")


class Packages:
    """Collects packages per (ecosystem, name). Every exact version seen becomes its own asset (a monorepo can pin
    several); a package with only a version range is listed once without a version."""

    def __init__(self, ctx: Context) -> None:
        self.ctx = ctx
        self.items: dict[tuple[str, str], dict] = {}

    def add(self, ecosystem: str, name: str, version: str | None, rel: str, line: int | None = None, *, exact: bool, dev: bool = False,
            constraint: str | None = None) -> None:
        name = pypi_name(name) if ecosystem == "PyPI" else name
        if not name or name.startswith("__"):
            return
        item = self.items.setdefault((ecosystem, name), {"ecosystem": ecosystem, "name": name, "versions": {}, "files": [], "dev": dev,
                                                         "constraint": None, "line": line, "file": rel})
        if version and exact:
            version = version if ecosystem == "Go" else version.lstrip("v=")
            seen = item["versions"].setdefault(version, {"files": [], "line": line})
            if rel not in seen["files"]:
                seen["files"].append(rel)
        if constraint and not item["constraint"]:
            item["constraint"] = constraint
        if rel not in item["files"]:
            item["files"].append(rel)
        item["dev"] = item["dev"] and dev
        index = PYPI_INDEX if ecosystem == "PyPI" else NPM_INDEX if ecosystem == "npm" else {}
        tech = index.get(name.lower())
        if ecosystem == "Go":
            tech = GO_INDEX.get(name) or next((t for mod, t in GO_INDEX.items() if name.startswith(mod + "/")), None)
        # A lockfile also lists everything the direct dependencies pull in, which says little about what the code uses.
        method = "lockfile" if rel.rsplit("/", 1)[-1] in LOCKFILES else "dependency"
        pinned = version if version and exact else None
        if tech is not None:
            self.ctx.signal(tech.key, method, rel, line, package=name, version=pinned)
        provider = INTEGRATIONS.get(name.lower())
        if provider:
            self.ctx.signal(provider, method, rel, line, package=name, version=pinned)

    def flush(self) -> int:
        inv, repo = self.ctx.inventory, self.ctx.repo
        count = 0
        for item in self.items.values():
            for version, seen in (item["versions"] or {None: {"files": item["files"], "line": item["line"]}}).items():
                ident = purl(item["ecosystem"], item["name"], version)
                asset = inv.add("package", ident, f"{item['name']}@{version}" if version else item["name"], attributes={
                    "ecosystem": item["ecosystem"], "package": item["name"], "version": version, "constraint": item["constraint"],
                    "purl": ident, "declared_in": seen["files"], "dev_only": item["dev"]},
                    location=Location(seen["files"][0], seen["line"], "dependency"))
                inv.link(repo, asset, "DEPENDS_ON", via=seen["files"][0])
                count += 1
        return count


def _requirements(pk: Packages, rel: str, text: str) -> None:
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http://", "https://", ".", "/")):
            continue
        m = _REQ_LINE.match(line)
        if m:
            name, _extras, op, version = m.groups()
            pk.add("PyPI", name, version, rel, number, exact=op in ("==", "==="), constraint=f"{op}{version}" if op else None)


def _pep508(pk: Packages, rel: str, spec: str, *, dev: bool = False) -> None:
    m = _REQ_LINE.match(spec)
    if m:
        name, _extras, op, version = m.groups()
        pk.add("PyPI", name, version, rel, exact=op in ("==", "==="), dev=dev, constraint=f"{op}{version}" if op else None)


def _pyproject(pk: Packages, rel: str, text: str) -> None:
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return
    project = doc.get("project") or {}
    for spec in project.get("dependencies") or []:
        _pep508(pk, rel, spec)
    for group in (project.get("optional-dependencies") or {}).values():
        for spec in group:
            _pep508(pk, rel, spec, dev=True)
    for group in (doc.get("dependency-groups") or {}).values():
        for spec in group:
            if isinstance(spec, str):
                _pep508(pk, rel, spec, dev=True)
    poetry = (doc.get("tool") or {}).get("poetry") or {}
    sections = [(poetry.get("dependencies") or {}, False), (poetry.get("dev-dependencies") or {}, True)]
    sections += [((g.get("dependencies") or {}), True) for g in (poetry.get("group") or {}).values()]
    for deps, dev in sections:
        for name, spec in deps.items():
            if name.lower() == "python":
                continue
            version = spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else None)
            exact = bool(version and re.fullmatch(r"=?=?\d[\w.]*", version))
            pk.add("PyPI", name, (version or "").lstrip("=") or None, rel, exact=exact, dev=dev, constraint=version)


def _toml_lock(pk: Packages, rel: str, text: str) -> None:
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return
    for package in doc.get("package") or []:
        if isinstance(package, dict) and package.get("name") and package.get("version"):
            source = package.get("source")
            if rel.endswith("Cargo.lock"):
                if not source:
                    continue  # a crate of this workspace, not a dependency
                ecosystem = "crates.io"
            else:
                ecosystem = "PyPI"
                if isinstance(source, dict) and (source.get("editable") or source.get("virtual") or source.get("directory")):
                    continue  # the project itself or a local path
            pk.add(ecosystem, package["name"], str(package["version"]), rel, exact=True)


def _pipfile(pk: Packages, rel: str, text: str) -> None:
    if rel.endswith(".lock"):
        try:
            doc = json.loads(text)
        except ValueError:
            return
        for section, dev in (("default", False), ("develop", True)):
            for name, spec in (doc.get(section) or {}).items():
                version = (spec.get("version") or "").lstrip("=") if isinstance(spec, dict) else None
                pk.add("PyPI", name, version or None, rel, exact=bool(version), dev=dev)
        return
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return
    for section, dev in (("packages", False), ("dev-packages", True)):
        for name, spec in (doc.get(section) or {}).items():
            version = spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else None)
            exact = bool(version and version.startswith("=="))
            pk.add("PyPI", name, (version or "").lstrip("=") or None, rel, exact=exact, dev=dev, constraint=version)


def _package_json(pk: Packages, rel: str, text: str) -> None:
    try:
        doc = json.loads(text)
    except ValueError:
        return
    if not isinstance(doc, dict):
        return
    for section, dev in (("dependencies", False), ("devDependencies", True), ("optionalDependencies", False), ("peerDependencies", False)):
        for name, spec in (doc.get(section) or {}).items():
            spec = str(spec)
            exact = bool(re.fullmatch(r"\d[\w.\-+]*", spec))
            pk.add("npm", name, spec if exact else None, rel, exact=exact, dev=dev, constraint=spec)


def _package_lock(pk: Packages, rel: str, text: str) -> None:
    try:
        doc = json.loads(text)
    except ValueError:
        return
    packages = doc.get("packages") if isinstance(doc, dict) else None
    if isinstance(packages, dict):
        for path, meta in packages.items():
            if path and isinstance(meta, dict) and meta.get("version") and "node_modules/" in path:
                name = path.rsplit("node_modules/", 1)[1]
                pk.add("npm", name, meta["version"], rel, exact=True, dev=bool(meta.get("dev")))
    elif isinstance(doc, dict):  # lockfile v1
        for name, meta in (doc.get("dependencies") or {}).items():
            if isinstance(meta, dict) and meta.get("version"):
                pk.add("npm", name, meta["version"], rel, exact=True, dev=bool(meta.get("dev")))


def _pnpm_lock(pk: Packages, rel: str, text: str) -> None:
    # Keys look like "/name@1.2.3", "name@1.2.3" or "/@scope/name@1.2.3(peer@x)" under "packages:".
    in_packages = False
    for number, line in enumerate(text.splitlines(), 1):
        if re.match(r"^(packages|snapshots):\s*$", line):
            in_packages = line.startswith("packages")
            continue
        if in_packages:
            if re.match(r"^\S", line):
                in_packages = False
                continue
            m = re.match(r"^  ['\"]?/?((?:@[^/@\s]+/)?[^@/\s'\"]+)@(\d[^(:'\"\s]*)", line)
            if m:
                pk.add("npm", m.group(1), m.group(2), rel, number, exact=True)


def _yarn_lock(pk: Packages, rel: str, text: str) -> None:
    current: list[str] = []
    header = ""
    for number, line in enumerate(text.splitlines(), 1):
        if line and not line.startswith((" ", "#")):
            header = line
            current = [re.sub(r"^\"|\"$", "", part.strip()).rsplit("@", 1)[0] for part in line.rstrip(":").split(",")]
        m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
        if m and current:
            # Yarn 2+ lists the workspace's own packages ("name@workspace:.") with a placeholder version.
            if "use.local" not in m.group(1) and "@workspace:" not in header:
                pk.add("npm", current[0], m.group(1), rel, number, exact=True)
            current = []


def _go_mod(pk: Packages, rel: str, text: str) -> None:
    block = False
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            block = True
            continue
        if block and line == ")":
            block = False
            continue
        m = re.match(r"^(?:require\s+)?([\w.\-]+\.[\w.\-/]+)\s+(v[\w.\-+]+)", line) if (block or line.startswith("require ")) else None
        if m:
            pk.add("Go", m.group(1), m.group(2), rel, number, exact=True)


def _cargo_toml(pk: Packages, rel: str, text: str) -> None:
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return
    for section, dev in (("dependencies", False), ("dev-dependencies", True), ("build-dependencies", True)):
        for name, spec in (doc.get(section) or {}).items():
            version = spec if isinstance(spec, str) else (spec.get("version") if isinstance(spec, dict) else None)
            exact = bool(version and version.startswith("="))
            pk.add("crates.io", name, (version or "").lstrip("=") or None, rel, exact=exact, dev=dev, constraint=version)


def _gemfile_lock(pk: Packages, rel: str, text: str) -> None:
    for number, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^    ([A-Za-z0-9_\-.]+) \(([\d][^)\s]*)\)$", line)
        if m:
            pk.add("RubyGems", m.group(1), m.group(2), rel, number, exact=True)


def _composer(pk: Packages, rel: str, text: str) -> None:
    try:
        doc = json.loads(text)
    except ValueError:
        return
    if rel.endswith(".lock"):
        for section, dev in (("packages", False), ("packages-dev", True)):
            for p in doc.get(section) or []:
                if isinstance(p, dict) and p.get("name") and p.get("version"):
                    pk.add("Packagist", p["name"], str(p["version"]).lstrip("v"), rel, exact=True, dev=dev)
        return
    for section, dev in (("require", False), ("require-dev", True)):
        for name, spec in (doc.get(section) or {}).items():
            if "/" in name:
                exact = bool(re.fullmatch(r"v?\d[\w.\-]*", str(spec)))
                pk.add("Packagist", name, str(spec).lstrip("v") if exact else None, rel, exact=exact, dev=dev, constraint=str(spec))


def _pom(pk: Packages, rel: str, text: str) -> None:
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        return  # never expand entities from repository files
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return
    ns = {"m": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
    q = (lambda tag: f"m:{tag}") if ns else (lambda tag: tag)
    props = {}
    for prop in root.findall(f".//{q('properties')}/*", ns):
        props[prop.tag.split("}")[-1]] = (prop.text or "").strip()
    for dep in root.findall(f".//{q('dependencies')}/{q('dependency')}", ns):
        group, artifact = dep.findtext(q("groupId"), "", ns).strip(), dep.findtext(q("artifactId"), "", ns).strip()
        version = dep.findtext(q("version"), "", ns).strip()
        version = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), version)
        if group and artifact:
            exact = bool(version) and "$" not in version and not version.startswith("[")
            scope = dep.findtext(q("scope"), "", ns).strip()
            pk.add("Maven", f"{group}:{artifact}", version if exact else None, rel, exact=exact, dev=scope == "test")


def _gradle(pk: Packages, rel: str, text: str) -> None:
    for m in re.finditer(r"""(implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(?\s*["']([\w.\-]+):([\w.\-]+):([\w.\-]+)["']""", text):
        conf, group, artifact, version = m.groups()
        pk.add("Maven", f"{group}:{artifact}", version, rel, text.count("\n", 0, m.start()) + 1, exact=True, dev=conf.startswith("test"))


def _csproj(pk: Packages, rel: str, text: str) -> None:
    for m in re.finditer(r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"', text):
        pk.add("NuGet", m.group(1), m.group(2), rel, text.count("\n", 0, m.start()) + 1, exact=not m.group(2).startswith("["))


def handler(name: str):
    """The parser for a file name, or None."""
    lower = name.lower()
    if re.fullmatch(r"(.*requirements.*|constraints)\.(txt|in)", lower):
        return _requirements
    return {
        "pyproject.toml": _pyproject, "poetry.lock": _toml_lock, "uv.lock": _toml_lock, "cargo.lock": _toml_lock, "pipfile": _pipfile,
        "pipfile.lock": _pipfile, "package.json": _package_json, "package-lock.json": _package_lock, "npm-shrinkwrap.json": _package_lock,
        "pnpm-lock.yaml": _pnpm_lock, "yarn.lock": _yarn_lock, "go.mod": _go_mod, "cargo.toml": _cargo_toml, "gemfile.lock": _gemfile_lock,
        "composer.json": _composer, "composer.lock": _composer, "pom.xml": _pom, "build.gradle": _gradle, "build.gradle.kts": _gradle,
    }.get(lower) or (_csproj if lower.endswith((".csproj", ".fsproj", ".vbproj")) else None)

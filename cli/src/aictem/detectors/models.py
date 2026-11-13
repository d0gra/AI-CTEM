"""Model artifacts. Pickle-based files are disassembled with pickletools; nothing is ever unpickled."""

from __future__ import annotations

import hashlib
import io
import pickletools
import re
import zipfile
from pathlib import Path

from aictem.catalog import CODE_EXECUTION_FORMATS, MIN_MODEL_BYTES, MODEL_EXTENSIONS, MODEL_FILE_NAMES
from aictem.detectors import Context
from aictem.model import Finding, Location

MAX_SCAN_BYTES = 512 * 1024 * 1024
DANGEROUS_MODULES = {
    "os": "process and filesystem control", "posix": "process and filesystem control", "nt": "process and filesystem control",
    "subprocess": "process execution", "sys": "interpreter control", "builtins": "eval/exec/open/__import__", "__builtin__": "eval/exec/open/__import__",
    "runpy": "module execution", "importlib": "dynamic import", "pty": "terminal spawning", "socket": "network access", "shutil": "filesystem modification",
    "ctypes": "native code execution", "marshal": "code object loading", "pickle": "nested unpickling", "_pickle": "nested unpickling",
    "webbrowser": "launching URLs", "urllib": "network access", "requests": "network access", "http": "network access", "code": "interactive interpreter",
    "pip": "package installation", "timeit": "code execution", "operator": "attribute access gadget", "functools": "partial application gadget",
    "torch.hub": "remote code download",
}
SAFE_BUILTINS = {"set", "frozenset", "dict", "list", "tuple", "int", "float", "bool", "str", "bytes", "bytearray", "complex", "slice", "range", "object", "getattr"}
_STRING_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "SHORT_BINSTRING", "BINSTRING", "STRING"}


def pickle_imports(data: bytes) -> tuple[list[str], str | None]:
    imports: list[str] = []
    recent: list[str] = []
    try:
        for opcode, arg, _pos in pickletools.genops(io.BytesIO(data)):
            if opcode.name in _STRING_OPS and isinstance(arg, str):
                recent = [*recent[-1:], arg]
            elif opcode.name in ("GLOBAL", "INST") and isinstance(arg, str):
                imports.append(arg.replace(" ", ".", 1))
            elif opcode.name == "STACK_GLOBAL" and len(recent) == 2:
                imports.append(f"{recent[0]}.{recent[1]}")
            if len(imports) > 20000:
                break
    except Exception as exc:  # noqa: BLE001  (pickletools raises many types on truncated or non-pickle input)
        return sorted(set(imports)), f"{type(exc).__name__}: {exc}"[:200]
    return sorted(set(imports)), None


def dangerous(imports: list[str]) -> list[dict]:
    hits = []
    for ref in imports:
        module, _, name = ref.rpartition(".")
        for prefix, reason in DANGEROUS_MODULES.items():
            if module == prefix or module.startswith(prefix + "."):
                if prefix in ("builtins", "__builtin__") and name in SAFE_BUILTINS:
                    continue
                hits.append({"import": ref, "reason": reason})
                break
    return hits


def _streams(path: Path, fmt: str) -> list[tuple[str, bytes]]:
    if zipfile.is_zipfile(path):  # torch.save and keras archives
        with zipfile.ZipFile(path) as zf:
            return [(i.filename, zf.read(i)) for i in zf.infolist() if i.filename.endswith((".pkl", ".pickle")) and i.file_size <= 256 * 1024 * 1024]
    if fmt in ("pickle", "pytorch") or fmt == "binary":
        return [(path.name, path.read_bytes())]
    return []


TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|testdata)/")


def scan(ctx: Context, path: Path, rel: str) -> bool:
    fmt = MODEL_FILE_NAMES.get(path.name) or MODEL_EXTENSIONS.get(path.suffix.lower())
    if not fmt:
        return False
    size = path.stat().st_size
    if size < MIN_MODEL_BYTES:
        return False
    head = b""
    if fmt == "binary":
        with path.open("rb") as fh:  # the first bytes only: these files can be many gigabytes
            head = fh.read(8)
    if fmt == "binary" and head[:2] not in (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05") and not zipfile.is_zipfile(path):
        return False  # arbitrary .bin file, not a pickled model
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    asset = ctx.inventory.add("ai_model", f"{ctx.repo.identifier}/{rel}", f"Pickle file {path.name}" if fmt == "pickle" else f"Model artifact {path.name}",
                              attributes={"format": fmt, "path": rel, "size_bytes": size, "sha256": digest.hexdigest()},
                              ai={"managed": False}, location=Location(rel, None, "file"))
    ctx.inventory.link(ctx.repo, asset, "CONTAINS", via=rel)
    common = {"asset": asset.ref, "domain": "ai_model", "file": rel, "owasp_llm": "LLM03:2025", "atlas_technique": "AML.T0010"}
    executes = fmt in CODE_EXECUTION_FORMATS or (fmt in ("binary", "keras") and zipfile.is_zipfile(path))
    if executes and size <= MAX_SCAN_BYTES:
        imports: set[str] = set()
        errors = []
        try:
            for name, data in _streams(path, fmt):
                found, error = pickle_imports(data)
                imports.update(found)
                if error:
                    errors.append(f"{name}: {error}")
        except (OSError, zipfile.BadZipFile) as exc:
            errors.append(str(exc)[:200])
        hits = dangerous(sorted(imports))
        asset.attributes["pickle_imports"] = sorted(imports)[:100]
        if hits:
            ctx.inventory.finding(Finding(
                rule_id="ai.model.pickle_code_execution", title=f"File {rel} imports code-execution callables when loaded", severity="high",
                confidence="firm", cwe="CWE-502", description="The pickle stream references callables that run commands or code during unpickling "
                "(found by disassembly; the file was not loaded). This is how malicious models execute code; legitimate files rarely need these.",
                remediation="Do not load this file. Obtain the model from a verified source, or convert it to safetensors.",
                evidence={"dangerous_imports": hits[:20], "errors": errors[:5]}, **common))
        elif fmt in CODE_EXECUTION_FORMATS and not TEST_PATH.search(rel):  # fixtures are expected to be pickles
            ctx.inventory.finding(Finding(
                rule_id="ai.model.unsafe_serialization", title=f"File {rel} uses a format that can execute code when loaded", severity="medium",
                confidence="confirmed", cwe="CWE-502", description="Pickle-based formats run code during loading. No dangerous callables were found, "
                "but the format allows them, so a replaced file could execute code.", remediation="Store weights as safetensors.",
                evidence={"format": fmt}, **common))
    return True

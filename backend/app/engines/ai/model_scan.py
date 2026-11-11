"""Model artifact inspection.

Pickle-based formats (pickle, joblib, PyTorch checkpoints) execute Python callables while
loading. This module disassembles the pickle stream *without executing it* and reports the
callables it would import. A reference to a code-execution callable is strong evidence that
loading the file runs code, and is reported with the exact opcode evidence. It is not, by
itself, proof of malicious intent, and the absence of such references is not proof of safety.
"""

import hashlib
import io
import pickletools
import zipfile
from pathlib import Path

MAX_SCAN_BYTES = 512 * 1024 * 1024
# module (or module prefix) -> why importing from it during unpickling matters
DANGEROUS_MODULES = {
    "os": "process and filesystem control", "posix": "process and filesystem control", "nt": "process and filesystem control",
    "subprocess": "process execution", "sys": "interpreter control", "builtins": "eval/exec/open/__import__",
    "__builtin__": "eval/exec/open/__import__", "runpy": "module execution", "importlib": "dynamic import",
    "pty": "terminal spawning", "socket": "network access", "shutil": "filesystem modification", "ctypes": "native code execution",
    "marshal": "code object loading", "pickle": "nested unpickling", "_pickle": "nested unpickling", "webbrowser": "launching URLs",
    "urllib": "network access", "requests": "network access", "http": "network access", "ftplib": "network access",
    "smtplib": "network access", "code": "interactive interpreter", "pip": "package installation", "timeit": "code execution",
    "operator": "attribute access gadget (attrgetter/methodcaller)", "functools": "partial application gadget",
    "torch.hub": "remote code download", "numpy.testing._private.utils": "runstring code execution",
}
SAFE_BUILTINS = {"set", "frozenset", "dict", "list", "tuple", "int", "float", "bool", "str", "bytes", "bytearray", "complex",
                 "slice", "range", "object", "getattr"}
_STRING_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "SHORT_BINSTRING", "BINSTRING", "STRING"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def pickle_imports(data: bytes) -> tuple[list[str], str | None]:
    """Disassemble a pickle stream and return ('module.name' imports, error)."""
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
    except Exception as exc:  # truncated or non-pickle data
        return sorted(set(imports)), f"{type(exc).__name__}: {exc}"[:200]
    return sorted(set(imports)), None


def _pickle_streams(path: Path, fmt: str) -> list[tuple[str, bytes]]:
    if path.stat().st_size > MAX_SCAN_BYTES:
        return []
    if zipfile.is_zipfile(path):  # modern torch.save and keras archives
        streams = []
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.filename.endswith((".pkl", ".pickle")) and info.file_size <= 256 * 1024 * 1024:
                    streams.append((info.filename, zf.read(info)))
        return streams
    if fmt in ("pickle", "pytorch"):
        return [(path.name, path.read_bytes())]
    return []


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


def inspect(path: Path, fmt: str) -> dict:
    """Return {scanned, streams, imports, dangerous, errors, oversized}."""
    oversized = path.stat().st_size > MAX_SCAN_BYTES
    result: dict = {"scanned": False, "streams": 0, "imports": [], "dangerous": [], "errors": [], "oversized": oversized}
    if fmt not in ("pickle", "pytorch", "keras", "binary") or oversized:
        return result
    try:
        streams = _pickle_streams(path, fmt)
    except (OSError, zipfile.BadZipFile) as exc:
        result["errors"].append(str(exc)[:200])
        return result
    all_imports: set[str] = set()
    for name, data in streams:
        if fmt == "binary" and data[:2] not in (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"):
            continue
        imports, error = pickle_imports(data)
        all_imports.update(imports)
        result["streams"] += 1
        if error:
            result["errors"].append(f"{name}: {error}")
    result["scanned"] = result["streams"] > 0
    result["imports"] = sorted(all_imports)[:200]
    result["dangerous"] = dangerous(sorted(all_imports))
    return result

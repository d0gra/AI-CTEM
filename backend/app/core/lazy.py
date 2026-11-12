"""Deferred imports for heavy optional libraries.

The Anthropic SDK and boto3 together add roughly 50 MB to every process that imports them, but most
deployments use them rarely (Claude analysis, AWS posture). `lazy_import` returns the module object
at once and executes it on first attribute access, so `except anthropic.RateLimitError` and
monkeypatching in tests behave exactly as with a normal import.
"""

import importlib.util
import sys
from types import ModuleType


def lazy_import(name: str) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.find_spec(name)
    if spec is None or spec.loader is None:
        raise ImportError(f"No module named {name!r}")
    loader = importlib.util.LazyLoader(spec.loader)
    spec.loader = loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module

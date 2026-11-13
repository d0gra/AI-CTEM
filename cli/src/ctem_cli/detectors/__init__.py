"""Detectors read files and record assets, relationships, findings and AI usage signals."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ctem_cli.catalog import BY_KEY, Tech
from ctem_cli.model import Asset, Inventory, Location


@dataclass
class Signal:
    """One observed use of an AI technology."""

    tech: Tech
    method: str  # dependency | import | config | endpoint | secret | container | iac
    location: Location
    package: str | None = None
    version: str | None = None


@dataclass
class Context:
    root: Path
    inventory: Inventory
    repo: Asset
    repo_info: dict
    tracked: set[str] | None = None  # git-tracked paths, when git is available
    signals: list[Signal] = field(default_factory=list)
    models_referenced: dict[str, set[str]] = field(default_factory=dict)  # tech key -> model names
    agent_files: dict[str, dict] = field(default_factory=dict)  # rel path -> {frameworks, tools, flags, name, identifiers}
    tool_files: dict[str, list[dict]] = field(default_factory=dict)  # tools defined outside any agent definition
    mcp_tool_files: dict[str, list[dict]] = field(default_factory=dict)  # tool modules of MCP servers
    rag_markers: dict[str, list[str]] = field(default_factory=dict)  # rel path -> markers
    endpoints: dict[str, Location] = field(default_factory=dict)  # origin -> first location (self-hosted inference)
    ci_systems: set[str] = field(default_factory=set)
    languages: dict[str, int] = field(default_factory=dict)

    def signal(self, key: str, method: str, file: str, line: int | None = None, package: str | None = None, version: str | None = None) -> None:
        tech = BY_KEY.get(key)
        if tech is not None:
            self.signals.append(Signal(tech, method, Location(file, line, method), package, version))

    def is_tracked(self, rel: str) -> bool | None:
        return None if self.tracked is None else rel in self.tracked


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1

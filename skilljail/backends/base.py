from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..policy import Policy


@dataclass
class LaunchSpec:
    """Everything the runner needs to launch a command inside the jail."""

    argv_prefix: list[str]  # prepended to the user's argv
    files: dict[str, str] = field(default_factory=dict)  # relative filename → contents, written into run dir
    env: dict[str, str] = field(default_factory=dict)  # extra env
    notes: list[str] = field(default_factory=list)  # human-readable caveats for the audit record

    def argv(self, cmd: list[str], run_dir: str) -> list[str]:
        return [a.replace("{run_dir}", run_dir) for a in self.argv_prefix] + cmd


class Backend(ABC):
    name: str = "base"

    @abstractmethod
    def available(self) -> bool: ...

    def unavailable_reason(self) -> str:
        return "not available"

    @abstractmethod
    def build(self, policy: Policy, proxy_port: int | None) -> LaunchSpec:
        """Compile a Policy into a LaunchSpec. ``proxy_port`` None → no network at all."""

    def capabilities(self) -> dict[str, bool]:
        return {"fs": True, "exec": True, "net_allowlist": True, "env_scrub": True}

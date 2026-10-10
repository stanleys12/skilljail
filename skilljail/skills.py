"""Locate skill directories the way Claude Code does (project → user → plugins)."""

from __future__ import annotations

import os
from pathlib import Path

from .manifest import SKILL_FILE


def _candidates(workspace: str | None) -> list[Path]:
    home = Path.home()
    out: list[Path] = []
    if workspace:
        ws = Path(workspace)
        for p in [ws, *ws.parents]:
            out.append(p / ".claude" / "skills")
            if p == home or p == Path("/"):
                break
    out.append(home / ".claude" / "skills")
    plugins = home / ".claude" / "plugins"
    if plugins.exists():
        out.append(plugins)
    extra = os.environ.get("SKILLJAIL_SKILL_PATH")
    if extra:
        out.extend(Path(x) for x in extra.split(":") if x)
    return out


def resolve_skill_dir(name: str, workspace: str | None = None, max_depth: int = 7) -> Path | None:
    """Find ``<root>/**/<name>/SKILL.md``. Handles ``plugin:skill`` and leading '/'."""
    name = name.strip().lstrip("/")
    plugin = None
    if ":" in name:
        plugin, name = name.rsplit(":", 1)
    if not name or "/" in name or name.startswith("."):
        return None
    p = Path(name)
    if p.is_dir() and (p / SKILL_FILE).exists():
        return p.resolve()
    for root in _candidates(workspace):
        if not root.is_dir():
            continue
        direct = root / name
        if not plugin and (direct / SKILL_FILE).exists():
            return direct.resolve()
        # nested (plugins, synced bundles): bounded walk
        for dirpath, dirnames, filenames in os.walk(root):
            depth = Path(dirpath).relative_to(root).parts
            if len(depth) >= max_depth:
                dirnames[:] = []
                continue
            if Path(dirpath).name == name and SKILL_FILE in filenames and (not plugin or plugin in depth):
                return Path(dirpath).resolve()
    return None


def list_skills(workspace: str | None = None, max_depth: int = 7) -> list[Path]:
    found: dict[str, Path] = {}
    for root in _candidates(workspace):
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            depth = Path(dirpath).relative_to(root).parts
            if len(depth) >= max_depth:
                dirnames[:] = []
                continue
            if SKILL_FILE in filenames:
                found.setdefault(str(Path(dirpath).resolve()), Path(dirpath).resolve())
    return sorted(found.values())

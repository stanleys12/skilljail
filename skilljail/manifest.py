"""Manifest schema and parsing.

A skill's permission manifest lives in one of two places (sidecar wins):

  1. ``<skill>/skilljail.yaml``            — sidecar, lets users manifest third-party skills
  2. ``<skill>/SKILL.md`` frontmatter      — top-level ``permissions:`` key

Everything is default-deny. An absent section grants nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

SIDECAR_NAME = "skilljail.yaml"
SKILL_FILE = "SKILL.md"
SCHEMA_VERSION = 1

# host[:port] | *.host[:port] | * | host:*   — no scheme, no path
_NET_RULE_RE = re.compile(
    r"^(?P<host>\*|(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*"
    r"|\d{1,3}(?:\.\d{1,3}){3}|\[[0-9A-Fa-f:]+\])"
    r"(?::(?P<port>\*|\d{1,5}))?$"
)
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CLASS_NAME_RE = re.compile(r"^[a-z][a-z0-9\-]*$")


class ManifestError(ValueError):
    """Raised when a manifest is syntactically or semantically invalid."""


@dataclass
class FsPerms:
    read: list[str] = field(default_factory=list)
    write: list[str] = field(default_factory=list)


@dataclass
class NetPerms:
    allow: list[str] = field(default_factory=list)


@dataclass
class ExecPerms:
    allow: list[str] = field(default_factory=list)
    shell: bool = False


@dataclass
class EnvPerms:
    # 'pass' is a keyword; keep the YAML key as `pass`
    pass_: list[str] = field(default_factory=list)


@dataclass
class Declaration:
    cls: str
    why: str


@dataclass
class Manifest:
    version: int = SCHEMA_VERSION
    fs: FsPerms = field(default_factory=FsPerms)
    net: NetPerms = field(default_factory=NetPerms)
    exec: ExecPerms = field(default_factory=ExecPerms)
    env: EnvPerms = field(default_factory=EnvPerms)
    declare: list[Declaration] = field(default_factory=list)
    # provenance
    source: str = "default"  # "sidecar" | "frontmatter" | "default" | "inferred"
    source_path: Path | None = None
    skill_name: str | None = None

    # ------------------------------------------------------------------ utils
    def declared_classes(self) -> set[str]:
        return {d.cls for d in self.declare}

    def is_empty(self) -> bool:
        return not (
            self.fs.read or self.fs.write or self.net.allow or self.exec.allow or self.env.pass_
        )

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"version": self.version}
        if self.fs.read or self.fs.write:
            d["fs"] = {}
            if self.fs.read:
                d["fs"]["read"] = list(self.fs.read)
            if self.fs.write:
                d["fs"]["write"] = list(self.fs.write)
        if self.net.allow:
            d["net"] = {"allow": list(self.net.allow)}
        if self.exec.allow or self.exec.shell:
            d["exec"] = {}
            if self.exec.allow:
                d["exec"]["allow"] = list(self.exec.allow)
            if self.exec.shell:
                d["exec"]["shell"] = True
        if self.env.pass_:
            d["env"] = {"pass": list(self.env.pass_)}
        if self.declare:
            d["declare"] = [{"class": x.cls, "why": x.why} for x in self.declare]
        return d

    def to_yaml(self, wrap_in_permissions: bool = False) -> str:
        body = self.to_dict()
        obj = {"permissions": body} if wrap_in_permissions else body
        return yaml.safe_dump(obj, sort_keys=False, default_flow_style=False)


# --------------------------------------------------------------------- parsing


def _as_str_list(value: Any, where: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        out: list[str] = []
        for i, v in enumerate(value):
            if not isinstance(v, str) or not v.strip():
                raise ManifestError(f"{where}[{i}] must be a non-empty string, got {v!r}")
            out.append(v.strip())
        return out
    raise ManifestError(f"{where} must be a string or list of strings, got {type(value).__name__}")


def validate_net_rule(rule: str) -> tuple[str, int | None]:
    """Return (host_pattern, port|None) or raise. ``port`` is None for 'default ports', -1 for '*'."""
    m = _NET_RULE_RE.match(rule)
    if not m:
        raise ManifestError(
            f"net.allow rule {rule!r} is invalid. Use host, *.host, host:port, host:*, or '*'. No scheme or path."
        )
    host = m.group("host").lower()
    port_s = m.group("port")
    if port_s is None:
        return host, None
    if port_s == "*":
        return host, -1
    port = int(port_s)
    if not 1 <= port <= 65535:
        raise ManifestError(f"net.allow rule {rule!r}: port out of range")
    return host, port


def parse_manifest_dict(data: Any, *, source: str = "dict", source_path: Path | None = None) -> Manifest:
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ManifestError(f"manifest must be a mapping, got {type(data).__name__}")

    known = {"version", "fs", "net", "exec", "env", "declare"}
    unknown = set(data) - known
    if unknown:
        raise ManifestError(f"unknown manifest keys: {sorted(unknown)} (allowed: {sorted(known)})")

    version = data.get("version", SCHEMA_VERSION)
    if version != SCHEMA_VERSION:
        raise ManifestError(f"unsupported manifest version {version!r}; this build supports {SCHEMA_VERSION}")

    fs_raw = data.get("fs") or {}
    if not isinstance(fs_raw, dict):
        raise ManifestError("fs must be a mapping with read/write lists")
    bad = set(fs_raw) - {"read", "write"}
    if bad:
        raise ManifestError(f"fs has unknown keys {sorted(bad)}")
    fs = FsPerms(read=_as_str_list(fs_raw.get("read"), "fs.read"), write=_as_str_list(fs_raw.get("write"), "fs.write"))
    for p in fs.read + fs.write:
        if "\x00" in p or p.strip() == "":
            raise ManifestError(f"invalid fs path {p!r}")

    net_raw = data.get("net") or {}
    if not isinstance(net_raw, dict):
        raise ManifestError("net must be a mapping with an allow list")
    bad = set(net_raw) - {"allow"}
    if bad:
        raise ManifestError(f"net has unknown keys {sorted(bad)}")
    net = NetPerms(allow=[r.lower() for r in _as_str_list(net_raw.get("allow"), "net.allow")])
    for r in net.allow:
        validate_net_rule(r)

    exec_raw = data.get("exec") or {}
    if not isinstance(exec_raw, dict):
        raise ManifestError("exec must be a mapping with allow list and optional shell flag")
    bad = set(exec_raw) - {"allow", "shell"}
    if bad:
        raise ManifestError(f"exec has unknown keys {sorted(bad)}")
    shell = exec_raw.get("shell", False)
    if not isinstance(shell, bool):
        raise ManifestError("exec.shell must be a boolean")
    ex = ExecPerms(allow=_as_str_list(exec_raw.get("allow"), "exec.allow"), shell=shell)

    env_raw = data.get("env") or {}
    if not isinstance(env_raw, dict):
        raise ManifestError("env must be a mapping with a pass list")
    bad = set(env_raw) - {"pass"}
    if bad:
        raise ManifestError(f"env has unknown keys {sorted(bad)}")
    env = EnvPerms(pass_=_as_str_list(env_raw.get("pass"), "env.pass"))
    for name in env.pass_:
        if not _ENV_NAME_RE.match(name):
            raise ManifestError(f"env.pass entry {name!r} is not a valid environment variable name")

    decl_raw = data.get("declare") or []
    if not isinstance(decl_raw, list):
        raise ManifestError("declare must be a list of {class, why}")
    declare: list[Declaration] = []
    for i, d in enumerate(decl_raw):
        if not isinstance(d, dict) or "class" not in d:
            raise ManifestError(f"declare[{i}] must be a mapping with 'class' and 'why'")
        cls = str(d["class"]).strip()
        why = str(d.get("why", "")).strip()
        if not _CLASS_NAME_RE.match(cls):
            raise ManifestError(f"declare[{i}].class {cls!r} is not a valid class name")
        if len(why) < 8:
            raise ManifestError(f"declare[{i}] for class {cls!r} needs a real justification in 'why' (>= 8 chars)")
        declare.append(Declaration(cls=cls, why=why))

    return Manifest(
        version=version, fs=fs, net=net, exec=ex, env=env, declare=declare, source=source, source_path=source_path
    )


_FRONTMATTER_RE = re.compile(r"\A---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|\Z)", re.DOTALL)


def split_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Return (frontmatter_dict, body). Frontmatter is optional."""
    m = _FRONTMATTER_RE.match(text)
    if not m:
        return {}, text
    try:
        fm = yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError as e:
        raise ManifestError(f"SKILL.md frontmatter is not valid YAML: {e}") from e
    if not isinstance(fm, dict):
        raise ManifestError("SKILL.md frontmatter must be a YAML mapping")
    return fm, text[m.end():]


def skill_name_from_dir(skill_dir: Path) -> str:
    skill_md = skill_dir / SKILL_FILE
    if skill_md.exists():
        try:
            fm, _ = split_frontmatter(skill_md.read_text(encoding="utf-8", errors="replace"))
            n = fm.get("name")
            if isinstance(n, str) and n.strip():
                return n.strip()
        except ManifestError:
            pass
    return skill_dir.name


def default_manifest(skill_name: str | None = None) -> Manifest:
    """The manifest an unmanifested skill gets: readable by the agent, executes nothing."""
    m = Manifest(source="default", skill_name=skill_name)
    m.fs.read = ["$SKILL"]
    return m


def load_manifest(skill_dir: Path) -> Manifest:
    """Load the manifest for a skill directory (sidecar > frontmatter > default)."""
    skill_dir = Path(skill_dir)
    if not skill_dir.is_dir():
        raise ManifestError(f"{skill_dir} is not a directory")
    name = skill_name_from_dir(skill_dir)

    sidecar = skill_dir / SIDECAR_NAME
    if sidecar.exists():
        try:
            data = yaml.safe_load(sidecar.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as e:
            raise ManifestError(f"{sidecar}: invalid YAML: {e}") from e
        # allow either bare manifest or {permissions: {...}}
        if isinstance(data, dict) and set(data) == {"permissions"}:
            data = data["permissions"]
        m = parse_manifest_dict(data, source="sidecar", source_path=sidecar)
        m.skill_name = name
        return m

    skill_md = skill_dir / SKILL_FILE
    if skill_md.exists():
        fm, _ = split_frontmatter(skill_md.read_text(encoding="utf-8", errors="replace"))
        if "permissions" in fm:
            m = parse_manifest_dict(fm["permissions"], source="frontmatter", source_path=skill_md)
            m.skill_name = name
            return m

    return default_manifest(name)

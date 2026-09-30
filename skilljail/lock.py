"""Rug-pull protection: bind an approved manifest to the exact skill content it was approved for.

``approve`` records a Merkle-ish hash of every file in the skill directory plus the manifest.
Activation recomputes and refuses on mismatch, naming the files that changed. A skill that
was benign at install and turns malicious on update (the ClawHavoc pattern) is stopped
before a single command runs.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SKILLJAIL_HOME = Path(os.environ.get("SKILLJAIL_HOME", os.path.expanduser("~/.skilljail")))
LOCKS_DIR = SKILLJAIL_HOME / "locks"
_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".mypy_cache", ".pytest_cache", ".DS_Store"}


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def file_hashes(skill_dir: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    skill_dir = Path(skill_dir)
    for root, dirs, files in os.walk(skill_dir):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)
        for fn in sorted(files):
            if fn in _SKIP_DIRS:
                continue
            p = Path(root) / fn
            if p.is_symlink():
                out[str(p.relative_to(skill_dir))] = "symlink:" + hashlib.sha256(os.readlink(p).encode()).hexdigest()
                continue
            try:
                out[str(p.relative_to(skill_dir))] = _sha256_file(p)
            except OSError:
                out[str(p.relative_to(skill_dir))] = "unreadable"
    return out


def tree_hash(hashes: dict[str, str]) -> str:
    h = hashlib.sha256()
    for rel in sorted(hashes):
        h.update(rel.encode("utf-8") + b"\0" + hashes[rel].encode() + b"\0")
    return h.hexdigest()


@dataclass
class Lock:
    name: str
    skill_dir: str
    tree_sha256: str
    manifest_sha256: str
    approved_at: float
    files: dict[str, str]
    risk_summary: dict[str, Any] = field(default_factory=dict)
    approved_by: str = "user"

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Lock":
        return cls(**{k: d[k] for k in cls.__dataclass_fields__ if k in d})


@dataclass
class LockStatus:
    status: str  # "approved" | "unapproved" | "changed"
    lock: Lock | None
    changed: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    manifest_changed: bool = False

    def describe(self) -> str:
        if self.status == "approved":
            return "content matches approved lock"
        if self.status == "unapproved":
            return "skill has never been approved (run `skilljail approve <dir>`)"
        parts = []
        if self.manifest_changed:
            parts.append("manifest changed")
        if self.changed:
            parts.append(f"modified: {', '.join(self.changed[:5])}{'…' if len(self.changed) > 5 else ''}")
        if self.added:
            parts.append(f"added: {', '.join(self.added[:5])}{'…' if len(self.added) > 5 else ''}")
        if self.removed:
            parts.append(f"removed: {', '.join(self.removed[:5])}{'…' if len(self.removed) > 5 else ''}")
        return "skill content changed since approval — " + "; ".join(parts)


def _lock_path(name: str, locks_dir: Path | None = None) -> Path:
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name)
    return (locks_dir or LOCKS_DIR) / f"{safe}.json"


def manifest_hash(manifest_dict: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(manifest_dict, sort_keys=True).encode()).hexdigest()


def approve(skill_dir: Path, name: str, manifest_dict: dict[str, Any], risk_summary: dict[str, Any] | None = None, locks_dir: Path | None = None) -> Lock:
    hashes = file_hashes(skill_dir)
    lock = Lock(
        name=name, skill_dir=str(Path(skill_dir).resolve()), tree_sha256=tree_hash(hashes),
        manifest_sha256=manifest_hash(manifest_dict), approved_at=time.time(), files=hashes,
        risk_summary=risk_summary or {},
    )
    p = _lock_path(name, locks_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(lock.to_dict(), indent=2), encoding="utf-8")
    return lock


def load_lock(name: str, locks_dir: Path | None = None) -> Lock | None:
    p = _lock_path(name, locks_dir)
    if not p.exists():
        return None
    try:
        return Lock.from_dict(json.loads(p.read_text(encoding="utf-8")))
    except (json.JSONDecodeError, TypeError, KeyError):
        return None


def check(skill_dir: Path, name: str, manifest_dict: dict[str, Any], locks_dir: Path | None = None) -> LockStatus:
    lock = load_lock(name, locks_dir)
    if lock is None:
        return LockStatus("unapproved", None)
    hashes = file_hashes(skill_dir)
    m_changed = manifest_hash(manifest_dict) != lock.manifest_sha256
    if tree_hash(hashes) == lock.tree_sha256 and not m_changed:
        return LockStatus("approved", lock)
    changed = sorted(k for k in hashes if k in lock.files and lock.files[k] != hashes[k])
    added = sorted(k for k in hashes if k not in lock.files)
    removed = sorted(k for k in lock.files if k not in hashes)
    return LockStatus("changed", lock, changed=changed, added=added, removed=removed, manifest_changed=m_changed)


def revoke(name: str, locks_dir: Path | None = None) -> bool:
    p = _lock_path(name, locks_dir)
    if p.exists():
        p.unlink()
        return True
    return False


def list_locks(locks_dir: Path | None = None) -> list[Lock]:
    d = locks_dir or LOCKS_DIR
    if not d.exists():
        return []
    out = []
    for p in sorted(d.glob("*.json")):
        try:
            out.append(Lock.from_dict(json.loads(p.read_text(encoding="utf-8"))))
        except Exception:
            continue
    return out

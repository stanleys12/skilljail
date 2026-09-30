"""Per-session ledger shared between hook invocations (each hook is a separate process).

The ledger is what makes multi-skill composition possible: it remembers which skills have
been active in this agent session, which sensitive classes they were allowed to read, and
which egress hosts they were allowed to reach. ``compose.py`` reads it at every activation.
"""

from __future__ import annotations

import fcntl
import json
import os
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator

SKILLJAIL_HOME = Path(os.environ.get("SKILLJAIL_HOME", os.path.expanduser("~/.skilljail")))
SESSIONS_DIR = SKILLJAIL_HOME / "sessions"


@dataclass
class ActiveSkill:
    name: str
    skill_dir: str
    workspace: str
    activated_at: float
    net_allow: list[str] = field(default_factory=list)
    classes_read: list[str] = field(default_factory=list)  # declared read-sensitive classes
    classes_write: list[str] = field(default_factory=list)
    exec_allow: list[str] = field(default_factory=list)
    manifest_source: str = "default"
    active: bool = True
    deactivated_at: float | None = None


@dataclass
class Session:
    session_id: str
    created_at: float
    workspace: str
    skills: list[ActiveSkill] = field(default_factory=list)
    ledger: list[dict[str, Any]] = field(default_factory=list)
    turn: int = 0

    # ----------------------------------------------------------------- queries
    @property
    def active_skills(self) -> list[ActiveSkill]:
        return [s for s in self.skills if s.active]

    @property
    def current(self) -> ActiveSkill | None:
        """Most recently activated skill (its profile governs Bash commands)."""
        act = self.active_skills
        return act[-1] if act else None

    def all_seen(self) -> list[ActiveSkill]:
        """Every skill this session has activated, active or not (context persists)."""
        return list(self.skills)

    def classes_read_so_far(self) -> set[str]:
        out: set[str] = set()
        for s in self.skills:
            out.update(s.classes_read)
        return out

    def egress_so_far(self) -> set[str]:
        out: set[str] = set()
        for s in self.skills:
            out.update(s.net_allow)
        return out

    # ---------------------------------------------------------------- mutation
    def record(self, kind: str, **detail: Any) -> None:
        self.ledger.append({"ts": time.time(), "turn": self.turn, "kind": kind, **detail})

    def activate(self, sk: ActiveSkill) -> None:
        # re-activation of the same skill dir refreshes its entry
        for s in self.skills:
            if s.skill_dir == sk.skill_dir and s.active:
                s.activated_at = sk.activated_at
                self.record("reactivate", skill=sk.name)
                return
        self.skills.append(sk)
        self.record("activate", skill=sk.name, net=sk.net_allow, classes_read=sk.classes_read)

    def deactivate_all(self, reason: str = "end-of-turn") -> int:
        n = 0
        now = time.time()
        for s in self.skills:
            if s.active:
                s.active = False
                s.deactivated_at = now
                n += 1
        if n:
            self.record("deactivate", count=n, reason=reason)
        return n

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Session":
        skills = [ActiveSkill(**s) for s in d.get("skills", [])]
        return cls(session_id=d["session_id"], created_at=d["created_at"], workspace=d.get("workspace", ""), skills=skills, ledger=d.get("ledger", []), turn=d.get("turn", 0))


def _path(session_id: str, sessions_dir: Path | None = None) -> Path:
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in session_id)[:80]
    return (sessions_dir or SESSIONS_DIR) / f"{safe}.json"


def load(session_id: str, workspace: str | None = None, sessions_dir: Path | None = None) -> Session:
    p = _path(session_id, sessions_dir)
    if p.exists():
        try:
            return Session.from_dict(json.loads(p.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
    return Session(session_id=session_id, created_at=time.time(), workspace=workspace or os.getcwd())


def save(sess: Session, sessions_dir: Path | None = None) -> Path:
    p = _path(sess.session_id, sessions_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(sess.to_dict(), indent=1), encoding="utf-8")
    os.replace(tmp, p)
    return p


def clear(session_id: str, sessions_dir: Path | None = None) -> bool:
    p = _path(session_id, sessions_dir)
    if p.exists():
        p.unlink()
        return True
    return False


@contextmanager
def locked(session_id: str, workspace: str | None = None, sessions_dir: Path | None = None) -> Iterator[Session]:
    """Load-modify-save under an exclusive file lock (hooks can fire concurrently)."""
    d = sessions_dir or SESSIONS_DIR
    d.mkdir(parents=True, exist_ok=True)
    lock_path = _path(session_id, d).with_suffix(".lock")
    with lock_path.open("w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            sess = load(session_id, workspace, d)
            yield sess
            save(sess, d)
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def list_sessions(sessions_dir: Path | None = None) -> list[Session]:
    d = sessions_dir or SESSIONS_DIR
    if not d.exists():
        return []
    out = []
    for p in sorted(d.glob("*.json")):
        try:
            out.append(Session.from_dict(json.loads(p.read_text(encoding="utf-8"))))
        except Exception:
            continue
    return out

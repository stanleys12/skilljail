"""Audit: JSONL run records + Seatbelt denial telemetry from the macOS unified log.

Seatbelt has no usable audit mode (``(trace)`` and ``(with report)`` are non-functional on
modern macOS), but the kernel logs every denial to the unified log as::

    kernel: (Sandbox) Sandbox: cat(24209) deny(1) file-read-data /Users/me/.aws/credentials

``DenialCollector`` runs ``/usr/bin/log stream`` for the duration of a jailed run and parses
those lines. It is *telemetry*, not enforcement: enforcement already happened in the kernel.
The value is that a blocked attempt becomes a named, classed audit event ("tried to read
cloud-creds") rather than a silent EPERM.

Filtering caveat: the unified log is system-wide. We keep entries in the run's time window
and drop a small set of chronically noisy system daemons. Entries are labeled with the
process name so a reviewer can judge attribution.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .classes import class_set

AUDIT_DIR = Path(os.environ.get("SKILLJAIL_HOME", os.path.expanduser("~/.skilljail"))) / "audit"

_DENY_RE = re.compile(
    r"Sandbox:\s+(?P<proc>[^\(]+)\((?P<pid>\d+)\)\s+deny\((?P<n>\d+)\)\s+(?P<op>[a-z\-\*]+)(?:\s+(?P<target>.*))?$"
)
# compact-style lines start with the *event* timestamp: "2026-09-30 04:24:47.245 E  kernel[...]"
_TS_RE = re.compile(r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2})\.(?P<ms>\d{3})")


def event_timestamp(line: str) -> float | None:
    m = _TS_RE.match(line)
    if not m:
        return None
    try:
        dt = datetime.strptime(f"{m.group('date')} {m.group('time')}", "%Y-%m-%d %H:%M:%S")
        return dt.timestamp() + int(m.group("ms")) / 1000.0
    except ValueError:
        return None
NOISY_PROCESSES = frozenset(
    {
        "bluetoothd", "parsecd", "mDNSResponder", "trustd", "cloudd", "nsurlsessiond", "commerce", "akd", "apsd",
        "identityservicesd", "rapportd", "sharingd", "WindowServer", "Spotlight", "mds", "mds_stores", "suggestd",
        "corespotlightd", "knowledge-agent", "siriknowledged", "assistantd", "photoanalysisd", "mediaanalysisd",
        "com.apple.WebKit.WebContent", "com.apple.WebKit.Networking", "Safari", "Google Chrome Helper", "Code Helper",
        "Code Helper (Renderer)", "Code Helper (GPU)", "Electron", "Slack Helper", "Discord Helper", "syspolicyd",
        "runningboardd", "diagnosticd", "logd", "UserEventAgent", "cfprefsd", "distnoted", "lsd", "secd", "nearbyd",
        "biomesyncd", "contextstored", "duetexpertd", "dasd", "coreduetd", "callservicesd", "IMDPersistenceAgent",
        "imagent", "CommCenter", "ContextStoreAgent", "intelligenceplatformd", "searchpartyd", "ControlCenter",
        "Finder", "Dock", "SystemUIServer", "NotificationCenter", "loginwindow", "coreaudiod", "audiomxd",
    }
)


@dataclass
class Denial:
    ts: float
    process: str
    pid: int
    op: str  # file-read-data, file-write-create, network-outbound, process-exec, mach-lookup, …
    target: str | None
    classes: list[str] = field(default_factory=list)

    @property
    def category(self) -> str:
        if self.op.startswith("file-read"):
            return "fs-read"
        if self.op.startswith("file-write") or self.op in ("file-ioctl", "file-link", "file-mount", "file-unmount"):
            return "fs-write"
        if self.op.startswith("network"):
            return "net"
        if self.op.startswith("process-exec"):
            return "exec"
        return "other"


def parse_denial_line(line: str, ts: float | None = None) -> Denial | None:
    m = _DENY_RE.search(line)
    if not m:
        return None
    target = (m.group("target") or "").strip() or None
    classes: list[str] = []
    if target and target.startswith("/"):
        classes = sorted(class_set(target))
    return Denial(
        ts=ts if ts is not None else time.time(),
        process=m.group("proc").strip(),
        pid=int(m.group("pid")),
        op=m.group("op"),
        target=target,
        classes=classes,
    )


class DenialCollector:
    """Reads Seatbelt denials from the macOS unified log for a run's time window.

    Uses a post-hoc ``log show --start … --end …`` query rather than a live ``log stream``:
    the persisted log is authoritative and deterministic, whereas the stream attaches with
    variable latency and can miss a single fast denial (e.g. a reverse shell's one blocked
    ``connect()``). This is telemetry only — enforcement already happened in the kernel.
    """

    def __init__(self, extra_noise: set[str] | None = None):
        self.available = sys.platform == "darwin" and shutil.which("log") is not None
        self._start_ts = 0.0
        self.noise = set(NOISY_PROCESSES) | (extra_noise or set())

    def start(self) -> None:
        self._start_ts = time.time()

    def _pump(self) -> None:  # retained for API compatibility; no-op in query mode
        pass

    @staticmethod
    def _fmt(ts: float) -> str:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

    def stop(self, settle: float | None = None, window_start: float | None = None, window_end: float | None = None) -> list[Denial]:
        """Return denials whose event time falls inside [window_start, window_end]."""
        if not self.available:
            return []
        if settle is None:
            settle = float(os.environ.get("SKILLJAIL_LOG_SETTLE", "0.6"))
        start = window_start if window_start is not None else self._start_ts
        end = window_end if window_end is not None else time.time()
        time.sleep(settle)  # let the kernel flush trailing denials to the log store
        try:
            proc = subprocess.run(
                ["/usr/bin/log", "show", "--style", "compact",
                 "--start", self._fmt(start - 1), "--end", self._fmt(end + 2),
                 "--predicate", 'sender == "Sandbox"'],
                capture_output=True, text=True, timeout=30,
            )
            lines = proc.stdout.splitlines()
        except Exception:
            return []
        out: list[Denial] = []
        for line in lines:
            ev_ts = event_timestamp(line)
            ts = ev_ts if ev_ts is not None else start
            if ts < start - 0.5 or ts > end + 2.5:
                continue
            d = parse_denial_line(line, ts)
            if d is None or d.process in self.noise:
                continue
            if d.target == "/dev/dtracehelper":  # harmless artifact of every sandboxed launch
                continue
            out.append(d)
        return out


@dataclass
class RunRecord:
    run_id: str
    skill: str
    skill_dir: str
    command: list[str]
    cwd: str
    backend: str
    started_at: str
    duration_s: float
    exit_code: int | None
    manifest_source: str
    policy_summary: dict[str, Any]
    proxy_events: list[dict[str, Any]]
    denials: list[dict[str, Any]]
    session_id: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def summary(self) -> dict[str, Any]:
        deny_by_cat: dict[str, int] = {}
        classes: set[str] = set()
        for d in self.denials:
            deny_by_cat[d["category"] if "category" in d else _cat(d["op"])] = deny_by_cat.get(
                d["category"] if "category" in d else _cat(d["op"]), 0
            ) + 1
            classes.update(d.get("classes", []))
        net_blocked = [e for e in self.proxy_events if e["decision"] in ("deny", "sink")]
        net_allowed = [e for e in self.proxy_events if e["decision"] == "allow"]
        return {
            "exit_code": self.exit_code,
            "duration_s": round(self.duration_s, 3),
            "denials": deny_by_cat,
            "sensitive_classes_attempted": sorted(classes),
            "net_allowed": len(net_allowed),
            "net_blocked": len(net_blocked),
            "net_blocked_hosts": sorted({f"{e['host']}:{e['port']}" for e in net_blocked}),
        }


def _cat(op: str) -> str:
    return Denial(0, "", 0, op, None).category


def write_record(rec: RunRecord, audit_dir: Path | None = None) -> Path:
    d = Path(audit_dir) if audit_dir else AUDIT_DIR
    d.mkdir(parents=True, exist_ok=True)
    path = d / (datetime.now(timezone.utc).strftime("%Y-%m-%d") + ".jsonl")
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec.to_dict(), ensure_ascii=False) + "\n")
    return path


def read_records(audit_dir: Path | None = None, limit: int = 50) -> list[dict[str, Any]]:
    d = Path(audit_dir) if audit_dir else AUDIT_DIR
    if not d.exists():
        return []
    recs: list[dict[str, Any]] = []
    for p in sorted(d.glob("*.jsonl"), reverse=True):
        for line in reversed(p.read_text(encoding="utf-8").splitlines()):
            if line.strip():
                try:
                    recs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            if len(recs) >= limit:
                return recs
    return recs

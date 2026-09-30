"""Runner: proxy + backend + scrubbed env + denial telemetry → one audited execution."""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import backends
from .audit import Denial, DenialCollector, RunRecord, write_record
from .manifest import Manifest
from .policy import Policy, PolicyError, assert_valid, build_policy
from .proxy import EgressProxy, NetPolicy, proxy_env

SAFE_ENV_PASSTHROUGH = ["PATH", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "COLORTERM", "TZ"]


@dataclass
class RunResult:
    record: RunRecord
    stdout: str | None
    stderr: str | None
    profile: str | None

    @property
    def exit_code(self) -> int | None:
        return self.record.exit_code

    @property
    def denials(self) -> list[dict[str, Any]]:
        return self.record.denials

    @property
    def net_blocked(self) -> list[dict[str, Any]]:
        return [e for e in self.record.proxy_events if e["decision"] in ("deny", "sink")]


def new_run_dir(prefix: str = "skilljail-") -> tuple[str, str]:
    """Create a per-run directory in the user's temp area (outside every sensitive class)."""
    run_dir = tempfile.mkdtemp(prefix=prefix)
    tmp = os.path.join(run_dir, "tmp")
    os.makedirs(tmp, exist_ok=True)
    return run_dir, tmp


def build_env(policy: Policy, proxy_port: int | None, base: dict[str, str] | None = None, overrides: dict[str, str] | None = None) -> dict[str, str]:
    src = base if base is not None else dict(os.environ)
    env: dict[str, str] = {}
    for k in SAFE_ENV_PASSTHROUGH:
        if k in src:
            env[k] = src[k]
    env["HOME"] = policy.home
    env["TMPDIR"] = policy.tmp_dir
    env["SHELL"] = "/bin/sh"
    env["SKILLJAIL"] = "1"
    env["SKILLJAIL_SKILL"] = policy.skill_name
    env["SKILLJAIL_SKILL_DIR"] = policy.skill_dir
    for k in policy.env_pass:
        if k in src:
            env[k] = src[k]
    if proxy_port:
        env.update(proxy_env(proxy_port))
    else:
        # belt and braces: point proxies at a closed port so proxy-aware tools fail fast
        env.update(proxy_env(1))
    if overrides:
        env.update(overrides)
    return env


def run_jailed(
    manifest: Manifest,
    skill_dir: str | os.PathLike,
    argv: list[str],
    *,
    workspace: str | os.PathLike | None = None,
    backend_name: str | None = None,
    mode: str = "enforce",
    home: str | None = None,
    env_base: dict[str, str] | None = None,
    env_overrides: dict[str, str] | None = None,
    capture: bool = False,
    timeout: float | None = None,
    stdin_data: str | None = None,
    session_id: str | None = None,
    write_audit: bool = True,
    collect_denials: bool = True,
    allow_errors: bool = False,
    strict_tmp: bool = False,
    audit_dir: Path | None = None,
    dial: bool = True,
) -> RunResult:
    """Execute ``argv`` under the skill's policy. Raises PolicyError if the policy has errors."""
    workspace = str(workspace or os.getcwd())
    run_dir, tmp = new_run_dir()
    policy = build_policy(manifest, skill_dir, workspace, tmp_dir=tmp, home=home, strict_tmp=strict_tmp)
    if not allow_errors:
        assert_valid(policy)
    return run_with_policy(
        policy, argv, run_dir=run_dir, backend_name=backend_name, mode=mode, env_base=env_base, env_overrides=env_overrides,
        capture=capture, timeout=timeout, stdin_data=stdin_data, session_id=session_id, write_audit=write_audit,
        collect_denials=collect_denials, audit_dir=audit_dir, dial=dial,
    )


def run_with_policy(
    policy: Policy,
    argv: list[str],
    *,
    run_dir: str,
    backend_name: str | None = None,
    mode: str = "enforce",
    env_base: dict[str, str] | None = None,
    env_overrides: dict[str, str] | None = None,
    capture: bool = False,
    timeout: float | None = None,
    stdin_data: str | None = None,
    session_id: str | None = None,
    write_audit: bool = True,
    collect_denials: bool = True,
    audit_dir: Path | None = None,
    dial: bool = True,
) -> RunResult:
    backend = backends.pick(backend_name)
    run_id = uuid.uuid4().hex[:12]
    started = time.time()

    proxy: EgressProxy | None = None
    port: int | None = None
    proxy_events: list[dict[str, Any]] = []
    # In enforce mode with no net rules we still start the proxy: it turns every attempt into a
    # logged 403 instead of an invisible connection-refused. In sink mode it records attempts.
    net_policy = NetPolicy.from_rules(policy.net_allow, allow_private=not dial)
    proxy = EgressProxy(net_policy, mode=mode, on_event=lambda e: proxy_events.append(e.__dict__), dial=dial)
    port = proxy.start()

    spec = backend.build(policy, port)
    for fname, content in spec.files.items():
        Path(run_dir, fname).write_text(content, encoding="utf-8")
    full_argv = spec.argv(argv, run_dir)
    env = build_env(policy, port, base=env_base, overrides={**spec.env, **(env_overrides or {})})

    collector = DenialCollector() if collect_denials else None
    if collector:
        collector.start()

    exit_code: int | None = None
    stdout = stderr = None
    notes = list(spec.notes)
    exec_started = time.time()
    try:
        proc = subprocess.run(
            full_argv, cwd=policy.workspace, env=env, capture_output=capture, text=True, timeout=timeout,
            input=stdin_data, stdin=None if stdin_data is not None else (subprocess.DEVNULL if capture else None),
        )
        exit_code = proc.returncode
        if capture:
            stdout, stderr = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        notes.append(f"timeout after {timeout}s; process killed")
        if capture:
            stdout = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
            stderr = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
    finally:
        exec_ended = time.time()
        denials: list[Denial] = collector.stop(window_start=exec_started, window_end=exec_ended) if collector else []
        if proxy:
            proxy.stop()

    duration = time.time() - started
    denial_dicts = []
    for d in denials:
        dd = d.__dict__.copy()
        dd["category"] = d.category
        denial_dicts.append(dd)

    rec = RunRecord(
        run_id=run_id, skill=policy.skill_name, skill_dir=policy.skill_dir, command=argv, cwd=policy.workspace,
        backend=backend.name, started_at=datetime.fromtimestamp(started, timezone.utc).isoformat(), duration_s=duration,
        exit_code=exit_code, manifest_source=policy.manifest_source, policy_summary=policy.summary(),
        proxy_events=proxy_events, denials=denial_dicts, session_id=session_id, notes=notes,
    )
    if write_audit:
        write_record(rec, audit_dir)
    profile = spec.files.get("profile.sb")
    return RunResult(record=rec, stdout=stdout, stderr=stderr, profile=profile)


def shell_argv(command: str) -> list[str]:
    """Wrap a shell command string the way Claude Code's Bash tool would run it."""
    return ["/bin/sh", "-c", command]


def format_denials(denials: list[dict[str, Any]], limit: int = 12) -> str:
    if not denials:
        return "  (none)"
    lines = []
    for d in denials[:limit]:
        cls = f"  [{', '.join(d['classes'])}]" if d.get("classes") else ""
        lines.append(f"  {d['process']}({d['pid']}) {d['op']} {d.get('target') or ''}{cls}")
    if len(denials) > limit:
        lines.append(f"  … {len(denials) - limit} more")
    return "\n".join(lines)


def format_argv(argv: list[str]) -> str:
    return " ".join(shlex.quote(a) for a in argv)

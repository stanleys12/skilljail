"""Claude Code lifecycle binding.

One command — ``skilljail hook`` — is registered for several events and dispatches on
``hook_event_name`` / ``tool_name``:

  PreToolUse  Skill                → resolve skill, load manifest, lock + composition check,
                                     allow/ask/deny, mark active in the session ledger
  PreToolUse  Bash                 → if a skill is active, rewrite the command to run inside
                                     the jail (kernel plane) via ``updatedInput``
  PreToolUse  Read|Write|Edit|…    → harness-plane path check against the active policy
  PreToolUse  WebFetch             → harness-plane host check
  Stop / SubagentStop / SessionEnd → deactivate skills (end of turn)
  SessionStart                     → fresh ledger

Config lives in ``~/.skilljail/config.json``::

  {"mode": "enforce" | "observe" | "off", "strict": false, "require_approval": true,
   "harness_plane": true, "unknown_skill": "allow" | "ask"}
"""

from __future__ import annotations

import json
import os
import shlex
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .. import compose, lock as lockmod, session as sessmod
from ..manifest import ManifestError, load_manifest
from ..policy import PolicyError, build_policy
from ..proxy import NetPolicy
from ..skills import resolve_skill_dir

SKILLJAIL_HOME = Path(os.environ.get("SKILLJAIL_HOME", os.path.expanduser("~/.skilljail")))
CONFIG_PATH = SKILLJAIL_HOME / "config.json"
DEFAULT_CONFIG: dict[str, Any] = {
    "mode": "enforce",
    "strict": False,
    "require_approval": True,
    "harness_plane": True,
    "unknown_skill": "allow",
    "exec_command": None,  # override for how hooks invoke skilljail (default: auto-detect)
    "log": True,
}
FS_TOOLS_READ = {"Read", "Glob", "Grep", "LS", "NotebookRead"}
FS_TOOLS_WRITE = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
HOOK_MARKER = "skilljail hook"


def load_config() -> dict[str, Any]:
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        try:
            cfg.update(json.loads(CONFIG_PATH.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError):
            pass
    return cfg


def save_config(cfg: dict[str, Any]) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def skilljail_command() -> str:
    cfg = load_config()
    if cfg.get("exec_command"):
        return cfg["exec_command"]
    import shutil

    exe = shutil.which("skilljail")
    if exe:
        return shlex.quote(exe)
    launcher = Path(__file__).resolve().parents[2] / "bin" / "skilljail"
    if launcher.is_file():
        return shlex.quote(str(launcher))
    return f"{shlex.quote(sys.executable)} -m skilljail.cli"


def _log(msg: str) -> None:
    try:
        d = SKILLJAIL_HOME / "hooks.log"
        d.parent.mkdir(parents=True, exist_ok=True)
        with d.open("a", encoding="utf-8") as f:
            f.write(msg.rstrip("\n") + "\n")
    except OSError:
        pass


def _pre(decision: str | None = None, reason: str | None = None, updated_input: dict | None = None, context: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"hookEventName": "PreToolUse"}
    if decision:
        out["permissionDecision"] = decision
    if reason:
        out["permissionDecisionReason"] = reason
    if updated_input is not None:
        out["updatedInput"] = updated_input
    if context:
        out["additionalContext"] = context[:9000]
    return {"hookSpecificOutput": out}


def _session_tmp(session_id: str) -> str:
    d = Path(tempfile.gettempdir()) / f"skilljail-{''.join(c for c in session_id if c.isalnum())[:24]}" / "tmp"
    d.mkdir(parents=True, exist_ok=True)
    return str(d)


def _skill_name_from_input(tool_input: dict[str, Any]) -> str | None:
    for k in ("skill", "name", "skill_name", "skillName", "command"):
        v = tool_input.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip().split()[0]
    return None


# ------------------------------------------------------------------ handlers


def handle(event: dict[str, Any]) -> dict[str, Any] | None:
    cfg = load_config()
    if cfg.get("mode") == "off":
        return None
    name = event.get("hook_event_name")
    session_id = event.get("session_id") or "no-session"
    cwd = event.get("cwd") or os.getcwd()

    if name == "SessionStart":
        with sessmod.locked(session_id, cwd) as s:
            if event.get("source") in ("startup", "clear"):
                s.skills.clear()
                s.ledger.clear()
            s.record("session-start", source=event.get("source"))
        return None

    if name in ("Stop", "SubagentStop", "SessionEnd"):
        with sessmod.locked(session_id, cwd) as s:
            n = s.deactivate_all(reason=name)
            s.turn += 1
        if name == "SessionEnd":
            sessmod.clear(session_id)
        if n and cfg.get("log"):
            _log(f"[{session_id[:8]}] {name}: deactivated {n} skill(s)")
        return None

    if name != "PreToolUse":
        return None

    tool = event.get("tool_name") or ""
    tool_input = event.get("tool_input") or {}

    if tool == "Skill":
        return _on_skill(event, cfg, session_id, cwd, tool_input)

    # everything else only matters while a skill is active
    sess = sessmod.load(session_id, cwd)
    cur = sess.current
    if cur is None:
        return None

    if tool == "Bash":
        return _on_bash(cfg, session_id, cwd, cur, tool_input)
    if cfg.get("harness_plane", True):
        if tool in FS_TOOLS_READ or tool in FS_TOOLS_WRITE:
            return _on_fs_tool(cfg, session_id, cwd, cur, tool, tool_input)
        if tool == "WebFetch":
            return _on_webfetch(cur, tool_input)
    return None


def _load_policy_for(cur: sessmod.ActiveSkill, session_id: str, cwd: str):
    manifest = load_manifest(Path(cur.skill_dir))
    return build_policy(manifest, cur.skill_dir, cur.workspace or cwd, tmp_dir=_session_tmp(session_id))


def _on_skill(event, cfg, session_id, cwd, tool_input) -> dict[str, Any] | None:
    skill_name = _skill_name_from_input(tool_input)
    if not skill_name:
        return None
    skill_dir = resolve_skill_dir(skill_name, cwd)
    if skill_dir is None:
        _log(f"[{session_id[:8]}] Skill {skill_name!r}: directory not found; {cfg.get('unknown_skill')}")
        if cfg.get("unknown_skill") == "ask":
            return _pre("ask", f"skilljail could not locate skill {skill_name!r} to enforce a manifest")
        return None
    try:
        manifest = load_manifest(skill_dir)
    except ManifestError as e:
        return _pre("deny", f"skilljail: manifest for {skill_name!r} is invalid: {e}")
    try:
        policy = build_policy(manifest, skill_dir, cwd, tmp_dir=_session_tmp(session_id))
    except PolicyError as e:
        return _pre("deny", f"skilljail: cannot build policy for {skill_name!r}: {e}")

    lock_status = lockmod.check(skill_dir, policy.skill_name, manifest.to_dict())
    sess = sessmod.load(session_id, cwd)
    decision = compose.evaluate_activation(policy, sess, lock_status, strict=bool(cfg.get("strict")), require_approval=bool(cfg.get("require_approval", True)))

    summary = policy.summary()
    touched = policy.classes_touched()
    jail_desc = (
        f"[skilljail] Skill '{policy.skill_name}' is running under a kernel-enforced least-privilege jail "
        f"(manifest: {manifest.source}). While it is active, every Bash command runs sandboxed: "
        f"fs.read={summary['fs_read'] or ['$SKILL only']}, fs.write={summary['fs_write'] or ['$TMP only']}, "
        f"net={summary['net_allow'] or 'none'}, exec={summary['exec'] or 'none'}. "
        f"Operations outside this set fail with 'Operation not permitted' — that is the jail working, not a bug; "
        f"do not try to work around it, tell the user the skill needs a manifest change."
    )
    if cfg.get("log"):
        _log(f"[{session_id[:8]}] Skill {policy.skill_name!r} @ {skill_dir}: {decision.action} — {decision.reason()} | lock={lock_status.status}")

    if decision.action == "deny":
        return _pre("deny", f"skilljail blocked skill '{policy.skill_name}': {decision.reason()}")
    # record activation (also on 'ask' — if the user approves, the skill will be active)
    with sessmod.locked(session_id, cwd) as s:
        s.activate(sessmod.ActiveSkill(
            name=policy.skill_name, skill_dir=str(skill_dir), workspace=cwd, activated_at=event.get("ts") or __import__("time").time(),
            net_allow=list(policy.net_allow), classes_read=sorted((touched["read"] | touched["read_covers"]) & policy.declared),
            classes_write=sorted((touched["write"] | touched["write_covers"]) & policy.declared),
            exec_allow=[e.original for e in policy.exec_rules], manifest_source=manifest.source,
        ))
    if decision.action == "ask":
        return _pre("ask", f"skilljail: skill '{policy.skill_name}' needs confirmation — {decision.reason()}", context=jail_desc)
    return _pre(None, None, context=jail_desc)


def _on_bash(cfg, session_id, cwd, cur: sessmod.ActiveSkill, tool_input) -> dict[str, Any] | None:
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return None
    if command.lstrip().startswith(("skilljail exec", "skilljail ")) or "SKILLJAIL_WRAPPED=1" in command:
        return None
    mode = cfg.get("mode", "enforce")
    wrapped = (
        f"SKILLJAIL_WRAPPED=1 {skilljail_command()} exec --session {shlex.quote(session_id)} --skill-dir {shlex.quote(cur.skill_dir)} "
        f"--workspace {shlex.quote(cwd)} --mode {mode} -- {shlex.quote(command)}"
    )
    new_input = dict(tool_input)
    new_input["command"] = wrapped
    if cfg.get("log"):
        _log(f"[{session_id[:8]}] Bash under {cur.name!r}: {command[:120]!r}")
    return _pre(None, None, updated_input=new_input, context=f"[skilljail] command runs inside the '{cur.name}' jail ({mode}).")


def _on_fs_tool(cfg, session_id, cwd, cur: sessmod.ActiveSkill, tool: str, tool_input) -> dict[str, Any] | None:
    path = tool_input.get("file_path") or tool_input.get("path") or tool_input.get("notebook_path")
    if not isinstance(path, str) or not path:
        if tool in ("Glob", "Grep"):
            path = cwd
        else:
            return None
    if not os.path.isabs(path):
        path = os.path.join(cwd, path)
    try:
        policy = _load_policy_for(cur, session_id, cwd)
    except (ManifestError, PolicyError) as e:
        return _pre("deny", f"skilljail: cannot evaluate policy for active skill {cur.name!r}: {e}")
    mode = "write" if tool in FS_TOOLS_WRITE else "read"
    ok, why = policy.path_allowed(path, mode)
    if cfg.get("log"):
        _log(f"[{session_id[:8]}] {tool} {path} under {cur.name!r}: {'allow' if ok else 'DENY'} — {why}")
    if ok:
        return None
    if cfg.get("mode") == "observe":
        return _pre(None, None, context=f"[skilljail observe] would deny {tool} {path}: {why}")
    return _pre("deny", f"skilljail (skill '{cur.name}'): {why}. The skill's manifest does not permit this path.")


def _on_webfetch(cur: sessmod.ActiveSkill, tool_input) -> dict[str, Any] | None:
    url = tool_input.get("url")
    if not isinstance(url, str):
        return None
    parts = urlsplit(url if "://" in url else "https://" + url)
    host = (parts.hostname or "").lower()
    port = parts.port or (443 if parts.scheme == "https" else 80)
    pol = NetPolicy.from_rules(cur.net_allow)
    if pol.match(host, port):
        return None
    return _pre("deny", f"skilljail (skill '{cur.name}'): WebFetch to {host}:{port} is not in net.allow {cur.net_allow or '[]'}")


# ------------------------------------------------------------------ install


def hook_entries(command: str) -> dict[str, list[dict[str, Any]]]:
    h = [{"type": "command", "command": command, "timeout": 30}]
    return {
        "SessionStart": [{"hooks": h}],
        "PreToolUse": [
            {"matcher": "Skill", "hooks": h},
            {"matcher": "Bash", "hooks": h},
            {"matcher": "Read|Write|Edit|MultiEdit|Glob|Grep|NotebookEdit|WebFetch", "hooks": h},
        ],
        "Stop": [{"hooks": h}],
        "SubagentStop": [{"hooks": h}],
        "SessionEnd": [{"hooks": h}],
    }


def _is_ours(entry: dict[str, Any]) -> bool:
    return any(HOOK_MARKER in (hk.get("command") or "") for hk in entry.get("hooks", []))


def install(settings_path: Path, command: str | None = None, dry_run: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
    command = command or f"{skilljail_command()} hook"
    settings: dict[str, Any] = {}
    if settings_path.exists():
        settings = json.loads(settings_path.read_text(encoding="utf-8") or "{}")
    before = json.loads(json.dumps(settings))
    hooks = settings.setdefault("hooks", {})
    for ev, entries in hook_entries(command).items():
        existing = [e for e in hooks.get(ev, []) if not _is_ours(e)]
        hooks[ev] = existing + entries
    if not dry_run:
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        if settings_path.exists():
            settings_path.with_suffix(".json.skilljail-backup").write_text(json.dumps(before, indent=2), encoding="utf-8")
        settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    return before, settings


def uninstall(settings_path: Path) -> bool:
    if not settings_path.exists():
        return False
    settings = json.loads(settings_path.read_text(encoding="utf-8") or "{}")
    hooks = settings.get("hooks") or {}
    changed = False
    for ev in list(hooks):
        kept = [e for e in hooks[ev] if not _is_ours(e)]
        if len(kept) != len(hooks[ev]):
            changed = True
        if kept:
            hooks[ev] = kept
        else:
            del hooks[ev]
    if changed:
        settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    return changed


def main_from_stdin() -> int:
    raw = sys.stdin.read()
    try:
        event = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return 0
    try:
        out = handle(event)
    except Exception as e:  # a crashing hook must never break the agent
        _log(f"hook error: {e!r} for event {event.get('hook_event_name')}/{event.get('tool_name')}")
        return 0
    if out:
        sys.stdout.write(json.dumps(out))
    return 0

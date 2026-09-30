"""skilljail command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from pathlib import Path

from . import __version__, compose
from . import lock as lockmod
from . import session as sessmod
from .audit import read_records
from .backends import BACKENDS, pick
from .infer import infer
from .manifest import SIDECAR_NAME, ManifestError, load_manifest
from .policy import PolicyError, build_policy
from .runner import format_denials, run_jailed, shell_argv
from .skills import list_skills, resolve_skill_dir


def _err(msg: str, code: int = 2) -> int:
    print(f"skilljail: {msg}", file=sys.stderr)
    return code


def _skill_dir(arg: str, workspace: str | None) -> Path:
    p = Path(arg)
    if p.is_dir():
        return p.resolve()
    r = resolve_skill_dir(arg, workspace)
    if r is None:
        raise SystemExit(_err(f"skill {arg!r} not found (not a directory, not under .claude/skills or ~/.claude/skills)"))
    return r


def _print_policy(policy, lock_status=None, decision=None, as_json=False) -> None:
    s = policy.summary()
    if as_json:
        out = {"policy": s}
        if lock_status is not None:
            out["lock"] = {"status": lock_status.status, "detail": lock_status.describe()}
        if decision is not None:
            out["decision"] = decision.to_dict()
        print(json.dumps(out, indent=2))
        return
    print(f"skill:      {s['skill']}   (manifest: {s['manifest_source']})")
    print(f"fs.read:    {s['fs_read'] or ['$SKILL (implicit)']}")
    print(f"fs.write:   {s['fs_write'] or ['$TMP (implicit)']}")
    print(f"net.allow:  {s['net_allow'] or 'none'}")
    print(f"exec:       {s['exec'] or 'none'}   shell={s['shell']}")
    print(f"env.pass:   {s['env_pass'] or 'none'}")
    if s["declared"]:
        print(f"declared:   {s['declared']}")
    if s["classes_read"] or s["classes_write"]:
        print(f"classes:    read={s['classes_read']} write={s['classes_write']}")
    risks = [r for r in s["risks"] if r["severity"] != "info"]
    if risks:
        print("risks:")
        for r in risks:
            print(f"  [{r['severity']}] {r['code']}: {r['message']}")
    if lock_status is not None:
        print(f"lock:       {lock_status.status} — {lock_status.describe()}")
    if decision is not None:
        print(compose.explain(decision))


# ------------------------------------------------------------------ commands


def cmd_run(a) -> int:
    skill_dir = _skill_dir(a.skill, a.workspace)
    try:
        manifest = load_manifest(skill_dir)
    except ManifestError as e:
        return _err(f"invalid manifest: {e}")
    argv = a.cmd
    if not argv:
        return _err("no command given (use: skilljail run --skill DIR -- cmd args…)")
    if len(argv) == 1 and (" " in argv[0] or "|" in argv[0] or ";" in argv[0]):
        argv = shell_argv(argv[0])
    try:
        res = run_jailed(
            manifest, skill_dir, argv, workspace=a.workspace, backend_name=a.backend, mode=a.mode, home=a.home,
            capture=False, timeout=a.timeout, allow_errors=a.allow_errors, strict_tmp=a.strict_tmp, write_audit=not a.no_audit,
        )
    except PolicyError as e:
        return _err(str(e))
    if a.verbose or res.denials or res.net_blocked:
        print(f"\n[skilljail] exit={res.exit_code}  denials={len(res.denials)}  net_blocked={len(res.net_blocked)}", file=sys.stderr)
        if res.denials:
            print("[skilljail] denied operations:", file=sys.stderr)
            print(format_denials(res.denials), file=sys.stderr)
        for e in res.net_blocked[:8]:
            print(f"[skilljail] net {e['decision']}: {e['method']} {e['host']}:{e['port']} — {e['reason']}", file=sys.stderr)
    return res.exit_code if res.exit_code is not None else 124


def cmd_exec(a) -> int:
    """Used by the Claude Code Bash hook rewrite."""
    skill_dir = Path(a.skill_dir).resolve()
    try:
        manifest = load_manifest(skill_dir)
    except ManifestError as e:
        return _err(f"invalid manifest: {e}")
    cmd = a.cmd
    if not cmd:
        return _err("no command")
    command = cmd[0] if len(cmd) == 1 else " ".join(shlex.quote(c) for c in cmd)
    mode = a.mode
    if mode == "observe":
        # observe: kernel jail off, proxy in enforce-log mode isn't possible without the jail; run unjailed but audit intent
        import subprocess

        print(f"[skilljail observe] running UNJAILED (observe mode): {command[:100]}", file=sys.stderr)
        return subprocess.call(["/bin/sh", "-c", command], cwd=a.workspace or os.getcwd())
    try:
        res = run_jailed(manifest, skill_dir, shell_argv(command), workspace=a.workspace, mode="enforce", capture=False, session_id=a.session, allow_errors=False)
    except PolicyError as e:
        print(f"skilljail: refusing to run — {e}", file=sys.stderr)
        return 126
    if res.denials or res.net_blocked:
        classes = sorted({c for d in res.denials for c in d.get("classes", [])})
        cats = {}
        for d in res.denials:
            cats[d["category"]] = cats.get(d["category"], 0) + 1
        hosts = sorted({f"{e['host']}:{e['port']}" for e in res.net_blocked})
        msg = f"[skilljail] jail '{res.record.skill}' denied {sum(cats.values())} op(s) {cats}"
        if classes:
            msg += f" touching sensitive classes {classes}"
        if hosts:
            msg += f"; blocked egress to {hosts}"
        msg += ". The skill manifest does not permit these; do not work around it."
        print(msg, file=sys.stderr)
    return res.exit_code if res.exit_code is not None else 124


def cmd_check(a) -> int:
    skill_dir = _skill_dir(a.skill, a.workspace)
    try:
        manifest = load_manifest(skill_dir)
    except ManifestError as e:
        return _err(f"invalid manifest: {e}")
    import tempfile

    tmp = tempfile.mkdtemp(prefix="skilljail-check-")
    try:
        policy = build_policy(manifest, skill_dir, a.workspace or os.getcwd(), tmp_dir=tmp)
    except PolicyError as e:
        return _err(str(e))
    lock_status = lockmod.check(skill_dir, policy.skill_name, manifest.to_dict())
    decision = compose.evaluate_activation(policy, None, lock_status, strict=a.strict)
    _print_policy(policy, lock_status, decision, as_json=a.json)
    return 0 if decision.action != "deny" else 1


def cmd_compile(a) -> int:
    skill_dir = _skill_dir(a.skill, a.workspace)
    manifest = load_manifest(skill_dir)
    import tempfile

    tmp = tempfile.mkdtemp(prefix="skilljail-compile-")
    policy = build_policy(manifest, skill_dir, a.workspace or os.getcwd(), tmp_dir=tmp)
    backend = pick(a.backend)
    spec = backend.build(policy, a.proxy_port)
    if spec.files:
        for name, content in spec.files.items():
            print(f";; ==== {name} ({backend.name})")
            print(content)
    print(";; argv prefix: " + " ".join(spec.argv_prefix))
    return 0


def cmd_infer(a) -> int:
    skill_dir = _skill_dir(a.skill, a.workspace)
    res = infer(skill_dir, minimal=a.minimal)
    if a.json:
        print(json.dumps(res.to_dict(), indent=2))
    else:
        print(res.report())
    if a.write:
        target = skill_dir / SIDECAR_NAME
        if target.exists() and not a.force:
            return _err(f"{target} exists; use --force to overwrite")
        target.write_text("# generated by `skilljail infer` — review every line before approving\n" + res.manifest.to_yaml(), encoding="utf-8")
        print(f"\nwrote {target}")
    return 0


def cmd_approve(a) -> int:
    skill_dir = _skill_dir(a.skill, a.workspace)
    try:
        manifest = load_manifest(skill_dir)
    except ManifestError as e:
        return _err(f"invalid manifest: {e}")
    import tempfile

    tmp = tempfile.mkdtemp(prefix="skilljail-approve-")
    try:
        policy = build_policy(manifest, skill_dir, a.workspace or os.getcwd(), tmp_dir=tmp)
    except PolicyError as e:
        return _err(str(e))
    if policy.errors and not a.force:
        _print_policy(policy)
        return _err("policy has errors; fix the manifest (or --force to approve anyway)")
    if manifest.source == "default" and not a.force:
        return _err("skill has no manifest (default policy executes nothing). Run `skilljail infer --write` first, or --force to approve the default")
    _print_policy(policy)
    if not a.yes:
        try:
            ans = input("\napprove this manifest and lock the skill's current content? [y/N] ")
        except EOFError:
            ans = "n"
        if ans.strip().lower() not in ("y", "yes"):
            print("not approved")
            return 1
    lk = lockmod.approve(skill_dir, policy.skill_name, manifest.to_dict(), risk_summary={"risks": [r.to_dict() for r in policy.risks]})
    print(f"approved {policy.skill_name}: {len(lk.files)} files locked (tree {lk.tree_sha256[:12]}…)")
    return 0


def cmd_revoke(a) -> int:
    ok = lockmod.revoke(a.name)
    print("revoked" if ok else "no lock found")
    return 0 if ok else 1


def cmd_locks(a) -> int:
    for lk in lockmod.list_locks():
        import datetime

        ts = datetime.datetime.fromtimestamp(lk.approved_at).strftime("%Y-%m-%d %H:%M")
        print(f"{lk.name:30s} {ts}  {len(lk.files):3d} files  {lk.tree_sha256[:12]}  {lk.skill_dir}")
    return 0


def cmd_compose(a) -> int:
    """Simulate activating skills in order within one session and print each decision."""
    import tempfile
    import time

    sess = sessmod.Session(session_id="simulated", created_at=time.time(), workspace=a.workspace or os.getcwd())
    rc = 0
    for name in a.skills:
        skill_dir = _skill_dir(name, a.workspace)
        manifest = load_manifest(skill_dir)
        tmp = tempfile.mkdtemp(prefix="skilljail-compose-")
        policy = build_policy(manifest, skill_dir, a.workspace or os.getcwd(), tmp_dir=tmp)
        ls = lockmod.check(skill_dir, policy.skill_name, manifest.to_dict())
        d = compose.evaluate_activation(policy, sess, ls, strict=a.strict, require_approval=not a.no_approval)
        print(f"\n→ activate {policy.skill_name}")
        print(compose.explain(d))
        if d.action == "deny":
            rc = 1
            continue
        t = policy.classes_touched()
        sess.activate(sessmod.ActiveSkill(
            name=policy.skill_name, skill_dir=str(skill_dir), workspace=sess.workspace, activated_at=time.time(),
            net_allow=list(policy.net_allow), classes_read=sorted((t["read"] | t["read_covers"]) & policy.declared),
            classes_write=sorted((t["write"] | t["write_covers"]) & policy.declared), exec_allow=[e.original for e in policy.exec_rules],
        ))
    return rc


def cmd_install(a) -> int:
    from .hooks.claude_code import install

    path = Path(a.settings or os.path.expanduser("~/.claude/settings.json"))
    before, after = install(path, command=a.command, dry_run=a.dry_run)
    if a.dry_run:
        print(json.dumps(after.get("hooks", {}), indent=2))
        print(f"\n(dry run — would write {path})")
    else:
        print(f"installed skilljail hooks into {path} (backup: {path.with_suffix('.json.skilljail-backup')})")
        print("Tip: add \"Bash(skilljail exec:*)\" to permissions.allow so jailed commands don't re-prompt.")
    return 0


def cmd_uninstall(a) -> int:
    from .hooks.claude_code import uninstall

    path = Path(a.settings or os.path.expanduser("~/.claude/settings.json"))
    print("removed" if uninstall(path) else "nothing to remove")
    return 0


def cmd_hook(a) -> int:
    from .hooks.claude_code import main_from_stdin

    return main_from_stdin()


def cmd_audit(a) -> int:
    recs = read_records(limit=a.last)
    if a.json:
        print(json.dumps(recs, indent=1))
        return 0
    for r in recs:
        from .audit import RunRecord

        rr = RunRecord(**{k: r.get(k) for k in RunRecord.__dataclass_fields__})
        s = rr.summary()
        cmd = " ".join(r["command"])[:70]
        print(f"{r['started_at'][:19]}  {r['skill']:22.22s} exit={s['exit_code']!s:4s} deny={sum(s['denials'].values()):3d} net⛔={s['net_blocked']:2d} {s['sensitive_classes_attempted'] or ''} :: {cmd}")
    return 0


def cmd_sessions(a) -> int:
    for s in sessmod.list_sessions():
        act = [x.name for x in s.active_skills]
        seen = [x.name for x in s.skills]
        print(f"{s.session_id[:12]:12s} turn={s.turn:3d} active={act} seen={seen} classes_read={sorted(s.classes_read_so_far())} egress={sorted(s.egress_so_far())}")
    return 0


def cmd_config(a) -> int:
    from .hooks.claude_code import load_config, save_config

    cfg = load_config()
    if a.key is None:
        print(json.dumps(cfg, indent=2))
        return 0
    if a.value is None:
        print(json.dumps(cfg.get(a.key)))
        return 0
    v: object = a.value
    if v in ("true", "false"):
        v = v == "true"
    elif v == "null":
        v = None
    cfg[a.key] = v
    save_config(cfg)
    print(f"{a.key} = {json.dumps(v)}")
    return 0


def cmd_skills(a) -> int:
    for p in list_skills(a.workspace):
        try:
            m = load_manifest(p)
            src = m.source
        except ManifestError:
            src = "INVALID"
        lk = lockmod.load_lock(p.name)
        print(f"{p.name:32.32s} manifest={src:11s} lock={'yes' if lk else 'no ':3s} {p}")
    return 0


def cmd_doctor(a) -> int:
    import platform
    import shutil
    import subprocess

    print(f"skilljail {__version__} on {platform.platform()} python {platform.python_version()}")
    for name, cls in BACKENDS.items():
        b = cls()
        print(f"backend {name:9s}: {'available' if b.available() else 'unavailable — ' + b.unavailable_reason()}  caps={b.capabilities()}")
    if sys.platform == "darwin":
        try:
            r = subprocess.run(["/usr/bin/sandbox-exec", "-p", "(version 1)(deny default)(allow process-exec)(allow process-fork)(allow file-read*)(allow sysctl-read)(allow mach-lookup)", "/bin/echo", "ok"], capture_output=True, text=True, timeout=10)
            print(f"sandbox-exec smoke: {'ok' if r.stdout.strip() == 'ok' else 'FAILED ' + r.stderr.strip()[:100]}")
        except Exception as e:
            print(f"sandbox-exec smoke: FAILED {e}")
        print(f"unified log telemetry: {'available' if shutil.which('log') else 'unavailable'} (/usr/bin/log stream)")
    from .hooks.claude_code import CONFIG_PATH, load_config

    print(f"config: {CONFIG_PATH} → {json.dumps(load_config())}")
    settings = Path(os.path.expanduser("~/.claude/settings.json"))
    if settings.exists():
        txt = settings.read_text(encoding="utf-8")
        print(f"claude code hooks: {'installed' if 'skilljail hook' in txt else 'not installed (run `skilljail install`)'}")
    return 0


def cmd_eval(a) -> int:
    from eval.harness import main as eval_main  # type: ignore

    return eval_main(a.eval_args)


# ------------------------------------------------------------------ parser


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="skilljail", description="Manifest-declared, kernel-enforced least privilege for agent skills.")
    p.add_argument("--version", action="version", version=f"skilljail {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def ws(sp):
        sp.add_argument("--workspace", "-w", help="workspace directory ($WORKSPACE); default cwd")

    s = sub.add_parser("run", help="run a command inside a skill's jail")
    s.add_argument("--skill", "-s", required=True, help="skill directory or name")
    ws(s)
    s.add_argument("--backend", choices=list(BACKENDS))
    s.add_argument("--mode", choices=["enforce", "sink"], default="enforce", help="sink = record egress attempts, never dial out (eval)")
    s.add_argument("--home", help="override $HOME (eval)")
    s.add_argument("--timeout", type=float)
    s.add_argument("--allow-errors", action="store_true", help="run even if the policy has errors (NOT recommended)")
    s.add_argument("--strict-tmp", action="store_true", help="do not expose the per-user DARWIN temp/cache dirs")
    s.add_argument("--no-audit", action="store_true")
    s.add_argument("--verbose", "-v", action="store_true")
    s.add_argument("cmd", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser("exec", help="(hook use) run a shell command inside the active skill's jail")
    s.add_argument("--session", default=None)
    s.add_argument("--skill-dir", required=True)
    ws(s)
    s.add_argument("--mode", choices=["enforce", "observe"], default="enforce")
    s.add_argument("cmd", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_exec)

    s = sub.add_parser("check", help="validate a skill's manifest and show its policy, risks, lock and decision")
    s.add_argument("skill")
    ws(s)
    s.add_argument("--strict", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("compile", help="print the compiled sandbox profile")
    s.add_argument("skill")
    ws(s)
    s.add_argument("--backend", choices=list(BACKENDS))
    s.add_argument("--proxy-port", type=int, default=0)
    s.set_defaults(fn=cmd_compile)

    s = sub.add_parser("infer", help="statically infer a manifest for a skill")
    s.add_argument("skill")
    ws(s)
    s.add_argument("--minimal", action="store_true", help="only evidence from code, not prose")
    s.add_argument("--write", action="store_true", help=f"write {SIDECAR_NAME} next to SKILL.md")
    s.add_argument("--force", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_infer)

    s = sub.add_parser("approve", help="approve a manifest and lock the skill's content hash")
    s.add_argument("skill")
    ws(s)
    s.add_argument("--yes", "-y", action="store_true")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_approve)

    s = sub.add_parser("revoke", help="remove a skill's approval lock")
    s.add_argument("name")
    s.set_defaults(fn=cmd_revoke)

    s = sub.add_parser("locks", help="list approved skills")
    s.set_defaults(fn=cmd_locks)

    s = sub.add_parser("compose", help="simulate activating several skills in one session")
    s.add_argument("skills", nargs="+")
    ws(s)
    s.add_argument("--strict", action="store_true")
    s.add_argument("--no-approval", action="store_true", help="don't require locks in the simulation")
    s.set_defaults(fn=cmd_compose)

    s = sub.add_parser("install", help="install Claude Code hooks")
    s.add_argument("--settings")
    s.add_argument("--command", help="override hook command")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(fn=cmd_install)

    s = sub.add_parser("uninstall", help="remove Claude Code hooks")
    s.add_argument("--settings")
    s.set_defaults(fn=cmd_uninstall)

    s = sub.add_parser("hook", help="(Claude Code) hook entrypoint; reads event JSON on stdin")
    s.set_defaults(fn=cmd_hook)

    s = sub.add_parser("audit", help="show recent jailed runs")
    s.add_argument("--last", type=int, default=30)
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_audit)

    s = sub.add_parser("sessions", help="show session ledgers")
    s.set_defaults(fn=cmd_sessions)

    s = sub.add_parser("config", help="get/set config (mode, strict, require_approval, harness_plane, unknown_skill)")
    s.add_argument("key", nargs="?")
    s.add_argument("value", nargs="?")
    s.set_defaults(fn=cmd_config)

    s = sub.add_parser("skills", help="list discoverable skills and their manifest/lock status")
    ws(s)
    s.set_defaults(fn=cmd_skills)

    s = sub.add_parser("doctor", help="check backends and installation")
    s.set_defaults(fn=cmd_doctor)

    s = sub.add_parser("eval", help="run the evaluation harness (see eval/)")
    s.add_argument("eval_args", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_eval)
    return p


def main(argv: list[str] | None = None) -> int:
    p = build_parser()
    a = p.parse_args(argv)
    # argparse REMAINDER keeps a leading '--'
    if hasattr(a, "cmd") and isinstance(a.cmd, list) and a.cmd and a.cmd[0] == "--":
        a.cmd = a.cmd[1:]
    if hasattr(a, "eval_args") and a.eval_args and a.eval_args[0] == "--":
        a.eval_args = a.eval_args[1:]
    try:
        return a.fn(a)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())

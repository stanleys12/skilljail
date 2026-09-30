"""Manifest → Policy: a fully resolved, platform-neutral permission set.

Normalization is where most sandbox bugs live, so this module is deliberately explicit:

* every path is variable-expanded, ``~``-expanded, and **canonicalized** with ``realpath``
  (``/tmp`` → ``/private/tmp`` on macOS; symlinked homes resolve). Seatbelt matches on the
  canonical path, so an uncanonicalized rule silently does nothing.
* glob rules become anchored regexes; the literal prefix before the first glob char is
  canonicalized.
* ``exec.allow`` names resolve through ``PATH`` to absolute binaries; interpreters that live
  in a versioned tree (Python.framework, venvs, Homebrew Cellar, nvm) are widened to that
  tree because they re-exec and dlopen inside it.
* every rule is classified against the sensitive-class registry; undeclared class contact
  is a policy *error* (fail closed), over-broad rules are *warnings*.
"""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import classes as C
from .manifest import Manifest, ManifestError

_GLOB_CHARS = set("*?[")
_VAR_RE = re.compile(r"\$\{?([A-Z_][A-Z0-9_]*)\}?")

# Binaries whose presence in exec.allow is a red flag regardless of the skill's purpose.
DANGEROUS_EXEC = {
    "sudo", "doas", "su", "osascript", "launchctl", "crontab", "at", "security", "defaults", "dscl", "chsh", "chflags",
    "nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp", "rsync", "sshpass", "tclsh", "expect",
    "sandbox-exec", "bwrap", "docker", "nsenter", "chroot", "systemctl", "kextload", "csrutil", "spctl", "xattr",
    "dd", "diskutil", "hdiutil", "tmutil", "pkill", "killall", "reboot", "shutdown",
}
NETWORK_CAPABLE_EXEC = {"curl", "wget", "python", "python3", "node", "ruby", "perl", "php", "git", "pip", "pip3", "npm", "npx", "pnpm", "yarn", "uv", "gh", "aws", "gcloud", "az"}
SHELLS = ["/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash", "/bin/ksh"]
_NO_WIDEN_PARENTS = {"/", "/usr", "/usr/local", "/opt", "/opt/homebrew", "/bin", "/sbin", "/System", "/Library"}


class PolicyError(ValueError):
    """Raised when a manifest cannot be turned into a safe policy."""


@dataclass
class Risk:
    code: str
    severity: str  # "error" | "high" | "warn" | "info"
    message: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "severity": self.severity, "message": self.message, **({"detail": self.detail} if self.detail else {})}


@dataclass
class PathRule:
    original: str
    path: str  # canonical absolute (for regex kind: the canonical literal prefix)
    kind: str  # "subpath" | "literal" | "regex"
    regex: str | None = None  # Python-dialect anchored regex (harness-plane checks)
    glob_tail: str | None = None  # raw glob after the canonical prefix (backends re-escape)
    classes: list[str] = field(default_factory=list)  # classes touched (inside/exact)
    covers: list[str] = field(default_factory=list)  # classes covered by an over-broad rule
    broad: bool = False


@dataclass
class ExecRule:
    original: str
    path: str  # canonical
    kind: str  # "literal" | "subpath"
    reason: str = ""


@dataclass
class Policy:
    skill_name: str
    skill_dir: str
    workspace: str
    tmp_dir: str
    home: str
    fs_read: list[PathRule]
    fs_write: list[PathRule]
    net_allow: list[str]
    exec_rules: list[ExecRule]
    shell: bool
    env_pass: list[str]
    declared: set[str]
    manifest_source: str
    risks: list[Risk] = field(default_factory=list)
    strict_tmp: bool = False

    # ------------------------------------------------------------- derived
    @property
    def errors(self) -> list[Risk]:
        return [r for r in self.risks if r.severity == "error"]

    @property
    def undeclared_read_classes(self) -> set[str]:
        return C.READ_SENSITIVE - self.declared

    @property
    def undeclared_write_classes(self) -> set[str]:
        return C.WRITE_SENSITIVE - self.declared

    def classes_touched(self) -> dict[str, set[str]]:
        out: dict[str, set[str]] = {"read": set(), "write": set(), "read_covers": set(), "write_covers": set()}
        for r in self.fs_read:
            out["read"].update(r.classes)
            out["read_covers"].update(r.covers)
        for r in self.fs_write:
            out["write"].update(r.classes)
            out["write_covers"].update(r.covers)
        return out

    def summary(self) -> dict[str, Any]:
        t = self.classes_touched()
        return {
            "skill": self.skill_name,
            "manifest_source": self.manifest_source,
            "fs_read": [r.original for r in self.fs_read],
            "fs_write": [r.original for r in self.fs_write],
            "net_allow": list(self.net_allow),
            "exec": sorted({e.original for e in self.exec_rules if e.original != "shell"}),
            "shell": self.shell,
            "env_pass": list(self.env_pass),
            "declared": sorted(self.declared),
            "classes_read": sorted(t["read"] | t["read_covers"]),
            "classes_write": sorted(t["write"] | t["write_covers"]),
            "risks": [r.to_dict() for r in self.risks],
        }

    # ------------------------------------------------------------- checks used by hooks
    def path_allowed(self, path: str, mode: str) -> tuple[bool, str]:
        """Harness-plane check for Read/Write/Edit tools. ``mode`` is 'read' or 'write'."""
        p = canonical(path)
        rules = self.fs_read if mode == "read" else self.fs_write
        if mode == "read":  # write implies read; writes list also grants read
            rules = rules + self.fs_write
        undeclared = self.undeclared_read_classes if mode == "read" else self.undeclared_write_classes
        hit_classes = C.class_set(p, self.home) & undeclared
        if hit_classes:
            return False, f"{mode} of {path} touches undeclared sensitive class(es): {', '.join(sorted(hit_classes))}"
        for r in rules:
            if _rule_matches(r, p):
                return True, f"allowed by fs.{mode} rule {r.original!r}"
        return False, f"{mode} of {path} is not covered by any fs.{mode} rule"


def _rule_matches(r: PathRule, p: str) -> bool:
    if r.kind == "literal":
        return p == r.path
    if r.kind == "subpath":
        return p == r.path or p.startswith(r.path.rstrip("/") + "/")
    if r.kind == "regex" and r.regex:
        return re.match(r.regex, p) is not None
    return False


# --------------------------------------------------------------------- helpers


def canonical(path: str) -> str:
    """realpath with a stable fallback for non-existent tails."""
    p = os.path.abspath(os.path.expanduser(path))
    real = os.path.realpath(p)
    return real.rstrip("/") or "/"


def expand_vars(raw: str, variables: dict[str, str]) -> str:
    def sub(m: re.Match) -> str:
        name = m.group(1)
        if name in variables:
            return variables[name]
        raise PolicyError(f"unknown path variable ${name} in {raw!r} (known: {', '.join('$' + k for k in variables)})")

    out = _VAR_RE.sub(sub, raw)
    if out.startswith("~"):
        out = variables.get("HOME", os.path.expanduser("~")) + out[1:]
    return out


def glob_to_regex(canon_prefix: str, glob_tail: str, escape=re.escape) -> str:
    """Anchored regex for ``<canon_prefix>/<glob_tail>``. ``**`` crosses '/', ``*`` and ``?`` do not.

    ``escape`` lets backends substitute their own regex-dialect escaper.
    """
    out = "^" + escape(canon_prefix.rstrip("/"))
    if glob_tail:
        out += "/" if not glob_tail.startswith("/") else ""
        i = 0
        while i < len(glob_tail):
            ch = glob_tail[i]
            if glob_tail.startswith("**", i):
                out += ".*"
                i += 2
                if i < len(glob_tail) and glob_tail[i] == "/":
                    i += 1
                continue
            if ch == "*":
                out += "[^/]*"
            elif ch == "?":
                out += "[^/]"
            elif ch == "[":
                j = glob_tail.find("]", i)
                if j == -1:
                    out += re.escape(ch)
                else:
                    out += glob_tail[i : j + 1]
                    i = j
            else:
                out += escape(ch)
            i += 1
    return out + "(/.*)?$"


def _make_path_rule(raw: str, variables: dict[str, str], home: str) -> PathRule:
    expanded = expand_vars(raw, variables)
    if not expanded.startswith("/"):
        # relative paths are relative to the workspace
        expanded = os.path.join(variables["WORKSPACE"], expanded)
    # split at first glob char (component boundary)
    idx = next((i for i, ch in enumerate(expanded) if ch in _GLOB_CHARS), -1)
    if idx == -1:
        canon = canonical(expanded)
        kind = "subpath"
        rule = PathRule(original=raw, path=canon, kind=kind)
    else:
        prefix = expanded[:idx].rsplit("/", 1)[0] or "/"
        tail = expanded[len(prefix) :].lstrip("/")
        canon = canonical(prefix)
        rule = PathRule(original=raw, path=canon, kind="regex", regex=glob_to_regex(canon, tail), glob_tail=tail)
    hits = C.classes_for_path(rule.path, home)
    # A skill may legitimately live inside an agent-config tree (~/.claude/skills/x); reading
    # its *own* directory is never a class violation.
    skill_root = variables.get("SKILL")
    inside_skill = bool(skill_root) and (rule.path == skill_root or rule.path.startswith(skill_root + "/"))
    rule.classes = [] if inside_skill else sorted({h.cls for h in hits if h.relation in ("inside", "exact")})
    rule.covers = sorted({h.cls for h in hits if h.relation == "covers"})
    rule.broad = rule.path in ("/", home, "/Users", "/home", os.path.dirname(home)) or (
        rule.kind == "regex" and rule.path in ("/", home)
    )
    return rule


def _widen_interpreter(real: str) -> tuple[str, str] | None:
    """If ``real`` sits in a versioned tree (…/bin/x), return (subpath, reason)."""
    parent = os.path.dirname(real)
    if os.path.basename(parent) != "bin":
        return None
    root = os.path.dirname(parent)
    if root in _NO_WIDEN_PARENTS or root.count("/") < 2:
        return None
    reason = "versioned tree"
    if "/Cellar/" in root:
        reason = "homebrew cellar"
    elif ".framework/Versions/" in root:
        reason = "framework"
    elif os.path.exists(os.path.join(root, "pyvenv.cfg")):
        reason = "python venv"
    elif "/.nvm/" in root or "/node/" in root:
        reason = "node version tree"
    return root, reason


def resolve_exec(name: str, path_env: str | None = None) -> list[ExecRule]:
    """Resolve an exec.allow entry to concrete rules (may be empty if not found)."""
    rules: list[ExecRule] = []
    if name.startswith("/") or name.startswith("~") or name.startswith("$"):
        candidate = os.path.expanduser(name)
        if not os.path.exists(candidate):
            return []
        real = canonical(candidate)
    else:
        found = shutil.which(name, path=path_env or os.environ.get("PATH"))
        if not found:
            return []
        real = canonical(found)
        # keep the PATH entry too (may be a symlink into a Cellar); Seatbelt checks the *resolved* path,
        # but the symlink must be readable to be resolved.
        if canonical(found) != found:
            rules.append(ExecRule(original=name, path=found, kind="literal", reason="path symlink"))
    rules.append(ExecRule(original=name, path=real, kind="literal", reason="resolved"))
    widened = _widen_interpreter(real)
    if widened:
        root, why = widened
        rules.append(ExecRule(original=name, path=root, kind="subpath", reason=why))
    # python venv → also the base interpreter it symlinks to (pyvenv.cfg 'home')
    if widened and widened[1] == "python venv":
        try:
            for line in open(os.path.join(widened[0], "pyvenv.cfg"), encoding="utf-8"):
                if line.startswith("home"):
                    base_bin = line.split("=", 1)[1].strip()
                    base = _widen_interpreter(os.path.join(base_bin, "python3"))
                    if base:
                        rules.append(ExecRule(original=name, path=base[0], kind="subpath", reason="venv base interpreter"))
        except OSError:
            pass
    return rules


# ------------------------------------------------------------------- builder


def build_policy(
    manifest: Manifest,
    skill_dir: str | os.PathLike,
    workspace: str | os.PathLike,
    *,
    tmp_dir: str | os.PathLike,
    home: str | None = None,
    path_env: str | None = None,
    strict_tmp: bool = False,
) -> Policy:
    home = canonical(home or os.path.expanduser("~"))
    skill_dir_c = canonical(str(skill_dir))
    workspace_c = canonical(str(workspace))
    tmp_c = canonical(str(tmp_dir))
    variables = {"SKILL": skill_dir_c, "WORKSPACE": workspace_c, "CWD": workspace_c, "TMP": tmp_c, "HOME": home}
    risks: list[Risk] = []

    def build_rules(raws: list[str], kind: str) -> list[PathRule]:
        out: list[PathRule] = []
        seen: set[tuple[str, str]] = set()
        for raw in raws:
            try:
                r = _make_path_rule(raw, variables, home)
            except PolicyError as e:
                raise PolicyError(f"fs.{kind}: {e}") from e
            key = (r.kind, r.regex or r.path)
            if key in seen:
                continue
            seen.add(key)
            out.append(r)
        return out

    fs_read = build_rules(manifest.fs.read, "read")
    fs_write = build_rules(manifest.fs.write, "write")

    # implicit: skill dir readable, private tmp read/write
    if not any(_rule_matches(r, skill_dir_c) for r in fs_read):
        fs_read.append(PathRule(original="$SKILL", path=skill_dir_c, kind="subpath"))
    if not any(_rule_matches(r, tmp_c) for r in fs_write):
        fs_write.append(PathRule(original="$TMP", path=tmp_c, kind="subpath"))

    declared = manifest.declared_classes()
    unknown = declared - C.ALL_CLASSES
    if unknown:
        raise PolicyError(f"declare: unknown class(es) {sorted(unknown)}; known: {sorted(C.ALL_CLASSES)}")

    # ---- class contact
    for r in fs_read:
        for cls in r.classes:
            if cls in C.READ_SENSITIVE and cls not in declared:
                risks.append(Risk("undeclared-class-read", "error", f"fs.read {r.original!r} reads sensitive class '{cls}' ({C.describe(cls)}) without a declare entry", {"rule": r.original, "class": cls}))
        for cls in r.covers:
            if cls in C.READ_SENSITIVE and cls not in declared:
                risks.append(Risk("broad-read-covers-class", "warn", f"fs.read {r.original!r} is broad enough to cover '{cls}'; SkillJail will carve it out (undeclared)", {"rule": r.original, "class": cls}))
        if r.broad:
            risks.append(Risk("over-broad-read", "warn", f"fs.read {r.original!r} grants read of an entire home/root tree", {"rule": r.original}))
    for r in fs_write:
        for cls in r.classes:
            if cls in C.WRITE_SENSITIVE and cls not in declared:
                risks.append(Risk("undeclared-class-write", "error", f"fs.write {r.original!r} writes sensitive class '{cls}' ({C.describe(cls)}) without a declare entry", {"rule": r.original, "class": cls}))
        for cls in r.covers:
            if cls in C.WRITE_SENSITIVE and cls not in declared:
                risks.append(Risk("broad-write-covers-class", "warn", f"fs.write {r.original!r} is broad enough to cover '{cls}'; SkillJail will carve it out (undeclared)", {"rule": r.original, "class": cls}))
        if r.broad:
            risks.append(Risk("over-broad-write", "high", f"fs.write {r.original!r} grants write to an entire home/root tree", {"rule": r.original}))
    for d in manifest.declare:
        risks.append(Risk("declared-class", "info", f"declares access to '{d.cls}': {d.why}", {"class": d.cls}))

    # ---- exec
    exec_rules: list[ExecRule] = []
    for name in manifest.exec.allow:
        base = os.path.basename(name)
        if base in DANGEROUS_EXEC:
            risks.append(Risk("dangerous-exec", "high", f"exec.allow includes {name!r}, a privilege/persistence/network primitive", {"exec": name}))
        elif base in NETWORK_CAPABLE_EXEC:
            risks.append(Risk("network-capable-exec", "info", f"exec.allow includes {name!r}, which can make network requests (gated by net.allow)", {"exec": name}))
        resolved = resolve_exec(name, path_env)
        if not resolved:
            risks.append(Risk("exec-unresolved", "warn", f"exec.allow {name!r} not found on PATH; it will be denied (fail closed)", {"exec": name}))
            continue
        exec_rules.extend(resolved)
    if manifest.exec.shell:
        for sh in SHELLS:
            if os.path.exists(sh):
                exec_rules.append(ExecRule(original="shell", path=canonical(sh), kind="literal", reason="exec.shell"))
        exec_rules.append(ExecRule(original="shell", path="/usr/bin/env", kind="literal", reason="shebang helper"))
    # de-dup
    seen_e: set[tuple[str, str]] = set()
    dedup: list[ExecRule] = []
    for e in exec_rules:
        if (e.kind, e.path) not in seen_e:
            seen_e.add((e.kind, e.path))
            dedup.append(e)
    exec_rules = dedup

    # write ∩ exec overlap → a skill could drop a binary and run it
    for w in fs_write:
        for e in exec_rules:
            overlap = (
                (w.kind == "subpath" and (e.path == w.path or e.path.startswith(w.path + "/")))
                or (e.kind == "subpath" and (w.path == e.path or w.path.startswith(e.path + "/")))
            )
            if overlap and e.original != "shell":
                risks.append(Risk("write-exec-overlap", "high", f"fs.write {w.original!r} overlaps exec path {e.path!r}: skill could modify what it executes", {"write": w.original, "exec": e.original}))
    # writes into any PATH directory
    for w in fs_write:
        for d in (path_env or os.environ.get("PATH", "")).split(":"):
            if d and w.kind == "subpath" and (canonical(d) == w.path or canonical(d).startswith(w.path + "/")):
                risks.append(Risk("write-into-path", "high", f"fs.write {w.original!r} covers PATH directory {d}", {"write": w.original, "dir": d}))
                break

    # ---- net
    for rule in manifest.net.allow:
        if rule == "*" or rule.startswith("*:"):
            risks.append(Risk("net-wildcard", "high", f"net.allow {rule!r} permits egress to any host", {"rule": rule}))
    if manifest.net.allow and not exec_rules:
        risks.append(Risk("net-without-exec", "info", "net.allow is set but nothing can execute; only harness-plane WebFetch will use it"))

    # ---- env
    for name in manifest.env.pass_:
        if re.search(r"(TOKEN|SECRET|KEY|PASS|CRED|AUTH)", name, re.I) and not manifest.net.allow:
            risks.append(Risk("secret-env-without-net", "info", f"env.pass {name} looks like a credential but the skill has no network access"))

    pol = Policy(
        skill_name=manifest.skill_name or os.path.basename(skill_dir_c),
        skill_dir=skill_dir_c, workspace=workspace_c, tmp_dir=tmp_c, home=home,
        fs_read=fs_read, fs_write=fs_write, net_allow=list(manifest.net.allow), exec_rules=exec_rules,
        shell=manifest.exec.shell, env_pass=list(manifest.env.pass_), declared=declared,
        manifest_source=manifest.source, risks=risks, strict_tmp=strict_tmp,
    )
    return pol


def assert_valid(policy: Policy) -> None:
    errs = policy.errors
    if errs:
        raise PolicyError("policy has errors:\n  - " + "\n  - ".join(r.message for r in errs))

"""macOS Seatbelt backend: Policy → SBPL profile → ``sandbox-exec -f profile -- cmd``.

Rule ordering matters: in SBPL the **last** matching rule wins, so the profile is laid out as

    (deny default)
    process/ipc basics
    system read baseline
    device nodes
    declared fs.read / fs.write / exec rules
    network: deny everything, allow only 127.0.0.1:<proxy>
    carve-outs: undeclared sensitive classes are denied *last*, so even an over-broad
                grant like fs.read: ["~"] cannot reach ~/.ssh
    hard denies: sandbox-exec, sudo, osascript, launchctl …

Verified on macOS 26.6 (Darwin 25.6). ``sandbox-exec`` is deprecated but still shipped and
still used by Anthropic's srt, OpenAI Codex CLI, and Chrome.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

from .. import classes as C
from ..policy import Policy, canonical, glob_to_regex
from .base import Backend, LaunchSpec

PROFILE_FILE = "profile.sb"
_SBPL_REGEX_SPECIAL = set(".^$*+?()[]{}|\\")


def sbpl_escape_regex(s: str) -> str:
    return "".join("\\" + ch if ch in _SBPL_REGEX_SPECIAL else ch for ch in s)


def q(s: str) -> str:
    """Quote a path for SBPL."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def rx(s: str) -> str:
    return '#"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


# Baseline read set: what any process needs to start and run. No user data lives here.
SYSTEM_READ_SUBPATHS = [
    "/usr", "/bin", "/sbin", "/System", "/Library", "/opt", "/Applications",
    "/private/var/db", "/private/etc", "/private/var/select", "/private/var/run",
    "/System/Volumes/Preboot/Cryptexes", "/System/Cryptexes", "/dev",
]
SYSTEM_READ_LITERALS = ["/", "/Users", "/private", "/private/tmp", "/private/var", "/private/var/folders", "/tmp", "/var", "/etc", "/home", "/Volumes"]
# System paths inside the baseline that are nevertheless sensitive → carved out.
SYSTEM_CARVEOUTS_READ = ["/Library/Keychains", "/private/var/db/SystemKey", "/private/etc/master.passwd", "/private/etc/sudoers", "/private/etc/sudoers.d", "/private/var/db/dslocal"]
HARD_DENY_EXEC = [
    "/usr/bin/sandbox-exec", "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/osascript", "/bin/launchctl", "/usr/bin/crontab",
    "/usr/bin/at", "/usr/bin/security", "/usr/bin/defaults", "/usr/bin/dscl", "/usr/bin/chsh", "/usr/sbin/diskutil",
    "/usr/bin/hdiutil", "/usr/bin/tmutil", "/usr/bin/kextload", "/usr/bin/csrutil", "/usr/sbin/spctl", "/sbin/reboot",
    "/sbin/shutdown", "/usr/bin/open",  # `open` launches unsandboxed apps via LaunchServices
]


def _real_home() -> str:
    import pwd

    try:
        return pwd.getpwuid(os.getuid()).pw_dir
    except Exception:
        return os.path.expanduser("~")


def _darwin_user_dir(name: str) -> str | None:
    try:
        out = subprocess.run(["/usr/bin/getconf", name], capture_output=True, text=True, timeout=5).stdout.strip()
        return canonical(out) if out else None
    except Exception:
        return None


class SeatbeltBackend(Backend):
    name = "seatbelt"

    def available(self) -> bool:
        return sys.platform == "darwin" and shutil.which("sandbox-exec") is not None

    def unavailable_reason(self) -> str:
        return "sandbox-exec is only available on macOS"

    # ------------------------------------------------------------------
    def compile(self, policy: Policy, proxy_port: int | None) -> str:
        L: list[str] = []
        a = L.append
        a("(version 1)")
        a(f";; skilljail profile for skill {policy.skill_name!r} — generated, do not edit")
        a("(deny default)")
        a("")
        a(";; ---- process & IPC basics")
        a("(allow process-fork)")
        a("(allow signal (target same-sandbox))")
        a("(allow sysctl-read)")
        a("(allow mach-lookup)")
        a("(allow ipc-posix*)")
        a("(allow process-info* (target same-sandbox))")
        a("(allow user-preference-read)")
        a("(allow pseudo-tty)")
        a("(allow file-read-metadata)")
        a("(allow system-fsctl)")
        a("")
        a(";; ---- device nodes")
        devs = ["/dev/null", "/dev/zero", "/dev/tty", "/dev/random", "/dev/urandom", "/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/dtracehelper", "/dev/fd", "/dev/ptmx", "/dev/autofs_nowait"]
        a("(allow file-read* file-write* file-ioctl " + " ".join(f"(literal {q(d)})" for d in devs) + ' (regex #"^/dev/ttys[0-9]+$") (regex #"^/dev/fd/[0-9]+$"))')
        a("")
        a(";; ---- system read baseline")
        a("(allow file-read* " + " ".join(f"(subpath {q(p)})" for p in SYSTEM_READ_SUBPATHS) + ")")
        a("(allow file-read* " + " ".join(f"(literal {q(p)})" for p in SYSTEM_READ_LITERALS) + ")")
        # harmless per-user files CoreFoundation reads on EVERY launch. macOS resolves these via
        # the real uid's home (getpwuid), not $HOME, so match by basename to catch both.
        a('(allow file-read* (regex #"/\\.CFUserTextEncoding$"))')
        for hp in {policy.home, _real_home()}:
            a(f"(allow file-read* (literal {q(hp + '/.CFUserTextEncoding')}))")
        if not policy.strict_tmp:
            for var in ("DARWIN_USER_TEMP_DIR", "DARWIN_USER_CACHE_DIR"):
                d = _darwin_user_dir(var)
                if d:
                    a(f"(allow file-read* file-write* (subpath {q(d)}))  ; {var}")
            # Non-sensitive cache dirs every toolchain writes on import/run. Not in any sensitive
            # class, not on PATH, not auto-executed — safe to grant so the jail doesn't break tools.
            # (Sensitive subdirs like ~/.config/gcloud are still carved out below.)
            for rel in (".cache", "Library/Caches", ".npm/_cacache", ".cargo/registry/cache", ".pyenv/cache", ".deno/cache", ".bun/install/cache", "Library/pnpm/store", ".cache/uv", ".cache/pip"):
                a(f"(allow file-read* file-write* (subpath {q(policy.home + '/' + rel)}))  ; cache")
        a("")
        a(";; ---- declared filesystem rules")
        for r in policy.fs_read:
            a(self._fs_rule("file-read*", r))
        for r in policy.fs_write:
            a(self._fs_rule("file-read* file-write*", r))
        a("")
        a(";; ---- declared exec rules (and read access to them)")
        if policy.exec_rules:
            lits = [e for e in policy.exec_rules if e.kind == "literal"]
            subs = [e for e in policy.exec_rules if e.kind == "subpath"]
            if lits:
                a("(allow process-exec " + " ".join(f"(literal {q(e.path)})" for e in lits) + ")")
                a("(allow file-read* " + " ".join(f"(literal {q(e.path)})" for e in lits) + ")")
            for e in subs:
                a(f"(allow process-exec (subpath {q(e.path)}))  ; {e.original}: {e.reason}")
                a(f"(allow file-read* (subpath {q(e.path)}))")
        else:
            a(";; (no exec permitted)")
        a("")
        a(";; ---- network: only the skilljail egress proxy")
        a("(deny network*)")
        if proxy_port:
            a(f'(allow network-outbound (remote ip "localhost:{proxy_port}"))')
        a("")
        a(";; ---- carve-outs: undeclared sensitive classes (last rule wins)")
        for cls in sorted(policy.undeclared_read_classes):
            for pat in C.CLASS_PATTERNS[cls]:
                a(self._deny_class("file-read*", pat, policy.home, cls))
        for cls in sorted(policy.undeclared_write_classes):
            for pat in C.CLASS_PATTERNS[cls]:
                a(self._deny_class("file-write*", pat, policy.home, cls))
        # …but the skill's own directory stays readable even if it lives under ~/.claude etc.
        a(f"(allow file-read* (subpath {q(policy.skill_dir)}))  ; skill dir always readable")
        for p in SYSTEM_CARVEOUTS_READ:
            a(f"(deny file-read* (subpath {q(p)}))")
        # the skill directory itself is never writable by the skill (self-modification → rug pull)
        a(f"(deny file-write* (subpath {q(policy.skill_dir)}))  ; skill dir is immutable while active")
        a("")
        a(";; ---- hard denies")
        a("(deny process-exec " + " ".join(f"(literal {q(p)})" for p in HARD_DENY_EXEC) + ")")
        a("(deny file-write* (subpath \"/System\") (subpath \"/usr\") (subpath \"/bin\") (subpath \"/sbin\") (subpath \"/Library\") (subpath \"/private/etc\"))")
        a("")
        return "\n".join(L) + "\n"

    def _fs_rule(self, ops: str, r) -> str:
        if r.kind == "literal":
            return f"(allow {ops} (literal {q(r.path)}))  ; {r.original}"
        if r.kind == "subpath":
            return f"(allow {ops} (subpath {q(r.path)}))  ; {r.original}"
        regex = glob_to_regex(r.path, r.glob_tail or "", escape=sbpl_escape_regex)
        return f"(allow {ops} (regex {rx(regex)}))  ; {r.original}"

    def _deny_class(self, ops: str, pat: str, home: str, cls: str) -> str:
        if pat.startswith("**/"):
            comp = sbpl_escape_regex(pat[3:])
            return f"(deny {ops} (regex {rx('(^|/)' + comp + '(/|$)')}))  ; class {cls}"
        root = os.path.normpath(home + pat[1:]) if pat.startswith("~") else os.path.normpath(pat)
        root = canonical(root) if os.path.exists(root) else root
        return f"(deny {ops} (subpath {q(root)}))  ; class {cls}"

    # ------------------------------------------------------------------
    def build(self, policy: Policy, proxy_port: int | None) -> LaunchSpec:
        profile = self.compile(policy, proxy_port)
        return LaunchSpec(
            argv_prefix=["/usr/bin/sandbox-exec", "-f", "{run_dir}/" + PROFILE_FILE, "--"],
            files={PROFILE_FILE: profile},
            notes=["seatbelt: last-matching-rule-wins ordering; undeclared classes carved out after grants"],
        )

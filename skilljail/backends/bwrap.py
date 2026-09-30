"""Linux bubblewrap backend (experimental — argv generation is unit-tested; not integration-tested here).

Mapping from Policy:
  fs.read  → ``--ro-bind path path``
  fs.write → ``--bind path path``
  exec     → PATH directories are replaced by a tmpfs, and only allowed binaries are
             bind-mounted back in (coarser than Seatbelt's process-exec, but effective)
  net      → ``--unshare-net``. The proxy is *not* reachable inside a fresh net namespace
             without a socket bridge (srt uses socat over a Unix socket); this backend
             therefore supports **no network** only. ``net.allow`` non-empty → error.
  env      → ``--clearenv`` then ``--setenv`` for the scrubbed set (runner supplies)

Undeclared sensitive classes are hidden with an empty tmpfs mounted over each root.
"""

from __future__ import annotations

import os
import shutil
import sys

from .. import classes as C
from ..policy import Policy
from .base import Backend, LaunchSpec

SYSTEM_RO = ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/etc", "/opt", "/var/lib", "/run/systemd/resolve"]


class BwrapBackend(Backend):
    name = "bwrap"

    def available(self) -> bool:
        return sys.platform.startswith("linux") and shutil.which("bwrap") is not None

    def unavailable_reason(self) -> str:
        return "bubblewrap (bwrap) not found or not on Linux"

    def capabilities(self) -> dict[str, bool]:
        return {"fs": True, "exec": True, "net_allowlist": False, "env_scrub": True}

    def build(self, policy: Policy, proxy_port: int | None) -> LaunchSpec:
        if policy.net_allow:
            raise RuntimeError("bwrap backend does not support net.allow yet (network is fully disabled); use the seatbelt backend on macOS for egress rules")
        argv = ["bwrap", "--die-with-parent", "--new-session", "--unshare-all", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", policy.home]
        for p in SYSTEM_RO:
            if os.path.exists(p):
                argv += ["--ro-bind", p, p]
        # exec allowlist: shadow PATH dirs with tmpfs, bind back allowed binaries
        path_dirs = [d for d in os.environ.get("PATH", "/usr/bin:/bin").split(":") if d]
        for d in path_dirs:
            if os.path.isdir(d):
                argv += ["--tmpfs", d]
        for e in policy.exec_rules:
            if os.path.exists(e.path):
                argv += ["--ro-bind", e.path, e.path]
        for r in policy.fs_read:
            if r.kind != "regex" and os.path.exists(r.path):
                argv += ["--ro-bind", r.path, r.path]
        for r in policy.fs_write:
            if r.kind != "regex":
                os.makedirs(r.path, exist_ok=True) if not os.path.exists(r.path) and r.path.startswith(policy.tmp_dir) else None
                if os.path.exists(r.path):
                    argv += ["--bind", r.path, r.path]
        # carve-outs: hide undeclared class roots
        for cls in sorted(policy.undeclared_read_classes | policy.undeclared_write_classes):
            for pat in C.CLASS_PATTERNS[cls]:
                if pat.startswith("**/"):
                    continue
                root = os.path.normpath(policy.home + pat[1:]) if pat.startswith("~") else pat
                if os.path.isdir(root):
                    argv += ["--tmpfs", root]
                elif os.path.isfile(root):
                    argv += ["--ro-bind", "/dev/null", root]
        argv += ["--chdir", policy.workspace, "--"]
        notes = ["bwrap: network fully disabled (no proxy bridge yet)", "bwrap: exec allowlist via tmpfs-shadowed PATH dirs (regex fs rules unsupported)"]
        return LaunchSpec(argv_prefix=argv, notes=notes)

"""Sensitive-path class registry.

A *class* names a family of paths whose access is a security event regardless of
what the skill claims to be doing. Touching a class in a manifest requires an explicit
``declare:`` entry with a justification; touching one at runtime without declaring it
is a denial the audit log calls out by class name, not just by path.

Patterns are matched against **canonical absolute paths**. Two directions matter:

* rule ⊆ class   — the rule is inside a sensitive root  (``~/.ssh/id_rsa``)
* class ⊆ rule   — the rule is a parent of a sensitive root (``~`` covers ``~/.ssh``)

Both count as "touching" the class; the second is also flagged as over-broad.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import PurePosixPath

# ``**/name`` = any path having a component (or trailing path) equal to ``name``.
# ``~/x``     = under the user's home. Absolute otherwise.
CLASS_PATTERNS: dict[str, list[str]] = {
    "ssh": ["~/.ssh"],
    "cloud-creds": ["~/.aws", "~/.config/gcloud", "~/.azure", "~/.oci", "~/.boto", "~/.config/doctl", "~/.fly"],
    "secrets": [
        "~/.netrc", "~/.npmrc", "~/.pypirc", "~/.gem/credentials", "~/.cargo/credentials", "~/.cargo/credentials.toml",
        "~/.docker/config.json", "~/.kube", "~/.terraform.d", "~/.vault-token", "~/.config/gh", "~/.config/op",
        "~/.config/hub", "~/.config/configstore", "~/.gnupg", "~/.password-store", "~/.local/share/keyrings",
        "**/.env", "**/.env.local", "**/.env.production", "**/.env.development", "**/secrets.json",
        "**/credentials.json", "**/service-account.json", "**/id_rsa", "**/id_ed25519", "**/.htpasswd",
        "**/.git-credentials",
    ],
    "keychain": ["~/Library/Keychains", "/Library/Keychains", "/private/var/db/SystemKey"],
    "browser": [
        "~/Library/Application Support/Google/Chrome", "~/Library/Application Support/BraveSoftware",
        "~/Library/Application Support/Firefox", "~/Library/Application Support/Microsoft Edge",
        "~/Library/Application Support/Arc", "~/Library/Safari", "~/Library/Cookies",
        "~/.mozilla", "~/.config/google-chrome", "~/.config/chromium", "~/.config/BraveSoftware",
    ],
    "shell-rc": [
        "~/.zshrc", "~/.zshenv", "~/.zprofile", "~/.zlogin", "~/.bashrc", "~/.bash_profile", "~/.bash_login",
        "~/.profile", "~/.config/fish", "~/.inputrc", "~/.hushlogin", "/etc/zshrc", "/etc/bashrc", "/etc/profile",
        "/private/etc/zshrc", "/private/etc/bashrc", "/private/etc/profile", "/private/etc/paths.d",
    ],
    "history": ["~/.zsh_history", "~/.bash_history", "~/.python_history", "~/.node_repl_history", "~/.lesshst", "~/.viminfo", "~/.zsh_sessions"],
    "agent-config": [
        "~/.claude", "~/.claude.json", "**/.claude", "~/.cursor", "**/.cursor", "~/.codex", "**/.codex",
        "~/.gemini", "**/.gemini", "~/.openclaw", "**/.openclaw", "~/.config/opencode", "**/.opencode",
        "~/.continue", "~/.aider.conf.yml", "**/.vscode", "**/.mcp.json", "**/AGENTS.md", "**/CLAUDE.md",
        "~/.skilljail", "~/.srt-settings.json", "~/.config/Code/User", "~/Library/Application Support/Code/User",
    ],
    "git-hooks": ["**/.git/hooks", "**/.git/config", "**/.gitconfig", "~/.gitconfig", "~/.config/git", "**/.gitattributes"],
    "launch-agents": [
        "~/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons", "/System/Library/LaunchDaemons",
        "~/.config/systemd", "/etc/systemd", "/etc/cron.d", "/etc/crontab", "/var/at", "/private/var/at",
        "~/.config/autostart", "/Library/StartupItems", "~/Library/Application Support/com.apple.backgroundtaskmanagementagent",
    ],
    "package-managers": [
        "/usr/local/bin", "/usr/local/lib", "/opt/homebrew/bin", "/opt/homebrew/lib", "/opt/homebrew/Cellar",
        "~/.local/bin", "~/.npm", "~/.nvm", "~/.pyenv", "~/.rbenv", "~/.cargo/bin", "~/go/bin", "~/.bun", "~/.deno",
        "~/.pnpm-store", "~/.yarn", "~/Library/Python", "~/.local/lib",
    ],
}

# Classes whose *read* is the dangerous direction (exfil sources). Shell rc files and agent
# configs are included because they routinely contain exported API keys / OAuth tokens.
READ_SENSITIVE = {"ssh", "cloud-creds", "secrets", "keychain", "browser", "history", "shell-rc", "agent-config"}
# Classes whose *write* is the dangerous direction (persistence / supply chain).
WRITE_SENSITIVE = {"shell-rc", "agent-config", "git-hooks", "launch-agents", "package-managers", "ssh", "cloud-creds", "secrets"}

ALL_CLASSES = frozenset(CLASS_PATTERNS)


@dataclass(frozen=True)
class ClassHit:
    cls: str
    pattern: str
    relation: str  # "inside" (rule ⊆ class) | "covers" (class ⊆ rule) | "exact"


def _norm(p: str) -> str:
    p = os.path.normpath(p)
    return p.rstrip("/") or "/"


def _expand(pattern: str, home: str) -> str:
    if pattern.startswith("~"):
        return _norm(home + pattern[1:])
    return _norm(pattern)


def _is_within(child: str, parent: str) -> bool:
    child = _norm(child)
    parent = _norm(parent)
    if parent == "/":
        return True
    return child == parent or child.startswith(parent + "/")


def _glob_component_hits(path: str, name_pattern: str) -> tuple[bool, bool]:
    """For ``**/name`` patterns. Returns (rule_inside_or_exact, rule_covers).

    ``name_pattern`` may be multi-component (``.git/hooks``).
    A path is "inside" if some suffix of its components starts with the pattern components.
    A path "covers" if it is a parent of a directory that *could* contain the pattern — we
    treat that as true only for very broad roots (home or '/'), handled by the caller.
    """
    comps = [c for c in PurePosixPath(_norm(path)).parts if c not in ("/", "")]
    pat = [c for c in PurePosixPath(name_pattern).parts if c not in ("/", "")]
    n = len(pat)
    for i in range(len(comps) - n + 1):
        if comps[i : i + n] == pat:
            return True, False
    return False, False


def classes_for_path(path: str, home: str | None = None) -> list[ClassHit]:
    """Return every class the given canonical absolute path touches."""
    home = _norm(home or os.path.expanduser("~"))
    path = _norm(path)
    hits: list[ClassHit] = []
    broad = path == "/" or path == home or _is_within(home, path)
    for cls, patterns in CLASS_PATTERNS.items():
        for pat in patterns:
            if pat.startswith("**/"):
                inside, _ = _glob_component_hits(path, pat[3:])
                if inside:
                    hits.append(ClassHit(cls, pat, "inside"))
                elif broad:
                    hits.append(ClassHit(cls, pat, "covers"))
                continue
            root = _expand(pat, home)
            if path == root:
                hits.append(ClassHit(cls, pat, "exact"))
            elif _is_within(path, root):
                hits.append(ClassHit(cls, pat, "inside"))
            elif _is_within(root, path):
                hits.append(ClassHit(cls, pat, "covers"))
    # de-duplicate by class keeping the most specific relation
    order = {"exact": 0, "inside": 1, "covers": 2}
    best: dict[str, ClassHit] = {}
    for h in hits:
        if h.cls not in best or order[h.relation] < order[best[h.cls].relation]:
            best[h.cls] = h
    return sorted(best.values(), key=lambda h: (order[h.relation], h.cls))


def class_set(path: str, home: str | None = None) -> set[str]:
    return {h.cls for h in classes_for_path(path, home)}


def describe(cls: str) -> str:
    return {
        "ssh": "SSH keys and known hosts",
        "cloud-creds": "cloud provider credentials (AWS/GCP/Azure/…)",
        "secrets": "API tokens, .env files, package-registry credentials",
        "keychain": "macOS keychain databases",
        "browser": "browser profiles (cookies, saved passwords, sessions)",
        "shell-rc": "shell startup files (persistence, PATH hijack)",
        "history": "shell/REPL history (often contains secrets)",
        "agent-config": "AI agent configuration, hooks, MCP servers, instructions",
        "git-hooks": "git hooks and config (code execution on next git command)",
        "launch-agents": "launchd/systemd/cron persistence",
        "package-managers": "binaries and libraries on PATH (supply-chain persistence)",
    }.get(cls, cls)

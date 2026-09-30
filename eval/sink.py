"""Safety substrate for the evaluation harness.

Two guarantees make it safe to *run* real malware while measuring it:

1. **Fake home with canaries.** Every run gets a throwaway ``$HOME`` seeded with decoy
   credentials (unique per run so a sink hit is unambiguously attributable). The real home
   is never on any allow-list, and the outer jail denies it regardless.
2. **The proxy never dials out in eval.** Baseline uses ``mode="sink"`` (everything recorded,
   nothing dialed). Enforcement uses ``mode="enforce", dial=False`` (disallowed hosts get a
   403 as in production; *allowed* hosts are sunk instead of dialed). So no packet from a
   skill under test ever reaches the internet.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Canaries:
    token_aws: str
    token_ssh: str
    token_env: str
    token_generic: str

    def all(self) -> list[str]:
        return [self.token_aws, self.token_ssh, self.token_env, self.token_generic]


PERSISTENCE_PROBES = [
    ".zshrc", ".bashrc", ".bash_profile", ".profile",
    ".config/fish/config.fish",
    "Library/LaunchAgents/probe.plist",
    ".claude/settings.json", ".claude/settings.local.json", ".claude.json",
    ".config/git/config", ".gitconfig",
]


@dataclass
class FakeHome:
    path: Path
    canaries: Canaries
    persistence_snapshot: dict[str, float] = field(default_factory=dict)

    def snapshot_persistence(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for rel in PERSISTENCE_PROBES:
            p = self.path / rel
            if p.exists():
                out[rel] = p.stat().st_mtime
        # also any file created under these dirs
        for d in (".claude", "Library/LaunchAgents", ".config/git", ".ssh/authorized_keys_dir"):
            dd = self.path / d
            if dd.is_dir():
                for f in dd.rglob("*"):
                    if f.is_file():
                        out[str(f.relative_to(self.path))] = f.stat().st_mtime
        return out

    def new_persistence(self) -> list[str]:
        now = self.snapshot_persistence()
        changed = []
        for rel, mt in now.items():
            if rel not in self.persistence_snapshot or self.persistence_snapshot[rel] != mt:
                changed.append(rel)
        return sorted(changed)

    def cleanup(self):
        shutil.rmtree(self.path, ignore_errors=True)


def make_fake_home(root: Path | None = None) -> FakeHome:
    base = Path(tempfile.mkdtemp(prefix="skilljail-eval-home-", dir=str(root) if root else None))
    rid = uuid.uuid4().hex[:10].upper()
    can = Canaries(
        token_aws=f"AKIA{rid}CANARYAWS",
        token_ssh=f"SSHCANARY{rid}PRIVKEY",
        token_env=f"ENVCANARY{rid}SECRET",
        token_generic=f"CANARY{rid}TOKEN",
    )
    # AWS
    (base / ".aws").mkdir(parents=True)
    (base / ".aws" / "credentials").write_text(
        f"[default]\naws_access_key_id = {can.token_aws}\naws_secret_access_key = {can.token_generic}wXYZ\n"
    )
    (base / ".aws" / "config").write_text("[default]\nregion = us-east-1\n")
    # SSH
    (base / ".ssh").mkdir(parents=True)
    (base / ".ssh" / "id_rsa").write_text(f"-----BEGIN OPENSSH PRIVATE KEY-----\n{can.token_ssh}\n-----END OPENSSH PRIVATE KEY-----\n")
    (base / ".ssh" / "id_rsa.pub").write_text(f"ssh-ed25519 {can.token_ssh}pub tester@host\n")
    (base / ".ssh" / "known_hosts").write_text("github.com ssh-ed25519 AAAA...\n")
    # dotfiles / shells / tokens
    (base / ".zshrc").write_text(f"export EDITOR=vim\nexport GH_TOKEN={can.token_generic}gh\n")
    (base / ".bashrc").write_text("export PS1='$ '\n")
    (base / ".netrc").write_text(f"machine api.example.com login tester password {can.token_generic}np\n")
    (base / ".npmrc").write_text(f"//registry.npmjs.org/:_authToken={can.token_generic}npm\n")
    (base / ".gitconfig").write_text("[user]\n  name = Tester\n  email = tester@example.com\n")
    # agent config
    (base / ".claude").mkdir(parents=True)
    (base / ".claude" / "settings.json").write_text('{"model": "claude-opus-4-8"}\n')
    (base / ".config" / "gcloud").mkdir(parents=True)
    (base / ".config" / "gcloud" / "credentials.db").write_text(f"gcp {can.token_generic}gcp\n")
    fh = FakeHome(path=base, canaries=can)
    fh.persistence_snapshot = fh.snapshot_persistence()
    return fh


def make_workspace(root: Path | None = None, canaries: Canaries | None = None) -> Path:
    ws = Path(tempfile.mkdtemp(prefix="skilljail-eval-ws-", dir=str(root) if root else None))
    (ws / "README.md").write_text("# Project\nA sample project.\n")
    (ws / "src").mkdir()
    (ws / "src" / "main.py").write_text("print('hello')\n")
    (ws / ".env").write_text(f"API_KEY={canaries.token_env if canaries else 'SECRET'}\nDATABASE_URL=postgres://u:p@db/x\n")
    (ws / "data").mkdir()
    (ws / "data" / "input.csv").write_text("a,b\n1,2\n")
    (ws / "docs").mkdir()
    (ws / "docs" / "guide.md").write_text("# Guide\n")
    return ws

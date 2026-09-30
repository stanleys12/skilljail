"""The gullible executor.

Simulates an agent that follows a skill's instructions to the letter. It extracts the
runnable payload from a skill package and executes it inside a jail. This is an *upper bound*
on agent compliance — a real agent sometimes refuses — which makes the containment numbers
conservative: we measure what happens when detection and agent judgment fail completely.

Payload sources, in order:
  1. every fenced ```bash/sh/console block in SKILL.md (and referenced *.md), concatenated
     and run as one script (so `cd`, exports and multi-step sequences work as written);
  2. each top-level script under scripts/ executed directly with its interpreter — many CI
     malware skills put the payload in a script the SKILL.md tells the agent to run.

Everything runs through ``skilljail.runner`` with the policy chosen by the harness.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from skilljail.infer import _fenced_blocks, _looks_like_shell, SHELL_LANGS
from skilljail.manifest import Manifest, split_frontmatter
from skilljail.policy import Policy
from skilljail.runner import RunResult, run_with_policy, new_run_dir, shell_argv
from skilljail.policy import build_policy


@dataclass
class Payload:
    kind: str  # "shell" | "script"
    label: str
    argv: list[str]
    interpreter: str | None = None


def extract_payloads(skill_dir: Path) -> list[Payload]:
    skill_dir = Path(skill_dir).resolve()
    payloads: list[Payload] = []

    # 1) shell blocks from SKILL.md + referenced markdown
    md_files = [skill_dir / "SKILL.md"] + sorted(skill_dir.glob("references/*.md"))
    shell_chunks: list[str] = []
    for md in md_files:
        if not md.exists():
            continue
        text = md.read_text(encoding="utf-8", errors="replace")
        _, body = split_frontmatter(text) if md.name == "SKILL.md" else ({}, text)
        for lang, code, _ in _fenced_blocks(body):
            if lang in SHELL_LANGS and (lang or _looks_like_shell(code)):
                # strip prompt markers
                cleaned = "\n".join(re.sub(r"^\s*[\$%>]\s", "", ln) for ln in code.splitlines())
                shell_chunks.append(cleaned)
    if shell_chunks:
        script = "set +e\n" + "\n".join(shell_chunks) + "\n"
        payloads.append(Payload(kind="shell", label="SKILL.md shell blocks", argv=shell_argv(script)))

    # 2) scripts run directly
    interp_by_ext = {".py": "python3", ".sh": "bash", ".bash": "bash", ".js": "node", ".mjs": "node", ".rb": "ruby", ".pl": "perl"}
    for sp in sorted((skill_dir / "scripts").glob("*")) if (skill_dir / "scripts").is_dir() else []:
        if sp.suffix in interp_by_ext and sp.is_file():
            interp = interp_by_ext[sp.suffix]
            payloads.append(Payload(kind="script", label=f"scripts/{sp.name}", argv=[interp, str(sp)], interpreter=interp))
    return payloads


@dataclass
class ExecOutcome:
    label: str
    exit_code: int | None
    net_events: list[dict] = field(default_factory=list)
    denials: list[dict] = field(default_factory=list)

    @property
    def external_hosts(self) -> set[str]:
        return {f"{e['host']}:{e['port']}" for e in self.net_events if e["decision"] in ("sink", "allow")}

    @property
    def blocked_hosts(self) -> set[str]:
        return {f"{e['host']}:{e['port']}" for e in self.net_events if e["decision"] == "deny"}


def run_payload(policy: Policy, payload: Payload, *, mode: str, dial: bool, env_base: dict, timeout: float = 25.0, collect_denials: bool = True) -> ExecOutcome:
    run_dir, _ = new_run_dir("skilljail-eval-")
    res: RunResult = run_with_policy(
        policy, payload.argv, run_dir=run_dir, mode=mode, dial=dial, env_base=env_base,
        capture=True, timeout=timeout, write_audit=False, collect_denials=collect_denials,
    )
    return ExecOutcome(label=payload.label, exit_code=res.exit_code, net_events=res.record.proxy_events, denials=res.record.denials)

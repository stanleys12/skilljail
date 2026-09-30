# SkillJail Threat Model

## What an attacker controls

The full contents of one or more skill packages the user installs: `SKILL.md` (natural-language
instructions **and** frontmatter), `scripts/`, `references/`, `assets/`. The attacker may also
control remote content the skill is told to fetch. This is the ClawHavoc / ToxicSkills reality:
skills are third-party packages, published to marketplaces, installed with roughly the trust of
an npm dependency, and ~37% of scanned ones have security flaws.

The payload may be **code** (a malicious `scripts/*.py`), **prose** (instructions in `SKILL.md`
that tell the agent to do something harmful — no code at all), or **mixed** (benign-looking
parts that are only dangerous combined). Detection-based defenses lose to the prose and mixed
cases; that is the motivation for containment.

## What the attacker does NOT control

- the agent harness binary (Claude Code) and its hook configuration;
- the operating system and its sandbox primitives (Seatbelt / Landlock);
- `skilljail` itself, its manifests-of-record, and the approval locks;
- the user's shell and environment *before* a skill is activated.

Trust assumption: the user (or their org) reviews and `approve`s a manifest once. Review is
cheap because the manifest is a few lines; `skilljail infer` drafts it and flags the scary bits.

## Assets

Credentials (`~/.aws`, `~/.ssh`, `.env`, keychain, browser cookies, `~/.npmrc`…), source code,
persistence footholds (shell rc, agent config/hooks, git hooks, launchd/cron, PATH dirs),
compute, and the integrity of the agent's future behavior.

## In scope — contained by design

| Behavior (MalSkillBench) | Mechanism |
|--------------------------|-----------|
| B1 data exfiltration | net default-deny; only declared hosts reach the proxy |
| B2 credential theft | fs read default-deny; credential classes never implicitly readable |
| B3 remote code execution | exec allowlist; net deny on the fetch step |
| B4 malware delivery | exec allowlist + net deny + write∉exec |
| B5 persistence | writes to shell-rc/agent-config/git-hooks/launchd classes denied unless declared |
| B6 reverse shell | only `127.0.0.1:‹proxy›` is reachable; the proxy speaks HTTP, not arbitrary TCP |
| B7 ransomware | fs write default-deny to declared paths only |
| B9 privilege escalation | `sudo`/`osascript`/`launchctl` non-executable; no sandbox nesting |

## Out of scope — by design, not by oversight

- **Permission reuse (B-any within declared scope).** A Vercel-deploy skill that deploys
  *attacker* code to *your* Vercel uses only its declared permissions. Containment bounds the
  blast radius to the declared surface; it does not judge intent inside it. Pair with review.
- **Agent-control attacks (B10–B15): role hijack, instruction override, goal hijack, prompt
  leak.** These manipulate the model through its context, not the OS. Containment of side
  effects still limits what a hijacked agent can *do*, but detecting the manipulation is a
  scanner's / guard-model's job. SkillJail is complementary to, not a replacement for, those.
- **Pure compute abuse (B8)** beyond what exec/net limits already curtail (no CPU/RAM quota in
  the Seatbelt backend).
- **Kernel 0-days.** Seatbelt and Landlock are OS-level, not a VM. A sandbox-escape CVE
  defeats them — as it does Codex CLI, Claude Code's own sandbox, and Chrome's renderer.
- **The harness plane is policy, not containment.** Read/Write/Edit/WebFetch run inside the
  agent process; SkillJail checks them with PreToolUse hooks and can be bypassed if the agent
  process itself is compromised. The kernel plane (every Bash command and its subprocesses) is
  the real boundary.

## Why containment beats detection here

A scanner must decide, for arbitrary English + code, whether the intent is malicious — an
open-ended classification with an irreducible miss rate, and the breach rate equals the miss
rate. SkillJail asks a bounded, local question — "does the declared purpose need `~/.ssh` or
`evil.example`?" — and enforces the answer in the kernel. A scanner miss is then not a breach:
the exfil host isn't routable and the credential file isn't readable, no matter how convincing
the instructions were.

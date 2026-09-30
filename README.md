# SkillJail

**Manifest-declared, kernel-enforced least privilege for AI agent skills.**

Agent skills (`SKILL.md` packages for Claude Code, OpenCode, Gemini CLI, …) are third-party
code *and* third-party instructions, installed with about the trust of an npm dependency.
Marketplaces host hundreds of thousands of them; audits find security flaws in ~37% and active
campaigns (ClawHavoc) ship credential-stealers. The dangerous part is often plain English, so
**scanners keep losing** — a payload-less `SKILL.md` that says "and also `cat ~/.aws/credentials`
and POST it for telemetry" carries no code to detect.

SkillJail stops asking *"is this skill malicious?"* and asks *"what does this skill need?"* —
then makes anything else **physically impossible at the kernel**, for exactly the lifetime of
the skill's activation. A scanner miss is no longer a breach: the exfil host isn't routable and
the credential file isn't readable, however convincing the instructions were.

```yaml
# skilljail.yaml  — the whole security model for a deploy skill
permissions:
  fs:   { read: ["$WORKSPACE"], write: ["$WORKSPACE/.vercel"] }
  net:  { allow: ["api.vercel.com", "registry.npmjs.org"] }
  exec: { allow: ["vercel", "npm", "node"], shell: true }
  env:  { pass: ["VERCEL_TOKEN"] }
```

Now `cat ~/.aws/credentials` → `Operation not permitted`; `curl evil.example` → connection
refused; `python -c 'socket…'` → cannot open a socket to anything but the audited egress proxy.
Nobody had to detect the attack.

## Why this is different from prior work

| Project | Manifest | Enforcement | Skill-lifecycle bound | Cross-skill |
|---------|----------|-------------|-----------------------|-------------|
| SkillGuard (2606.03024) | ✅ | tool-call **hooks** (bypassable below the hook) | ✅ | ❌ |
| skillsandbox (OSS MVP) | ✅ | kernel (iptables/seccomp) | ❌ (standalone jail) | ❌ |
| Claude Code `allowed-tools` | partial | grant-only, doesn't restrict | ✅ | ❌ |
| AgentBound (2510.21236) | ✅ | for **MCP servers**, not skills | — | ❌ |
| **SkillJail** | ✅ | **kernel** (Seatbelt/Landlock) + egress proxy | ✅ (PreToolUse `Skill`→`Stop`) | ✅ (R1 exfil-chain ledger) |

The gap SkillJail fills is the seam every prior tool misses from one side or the other:
**OS-level enforcement bound to skill activation, with cross-skill composition** — SkillGuard
has the manifest but enforces at the hook layer (a `Bash`-spawned subprocess escapes it);
skillsandbox has the kernel enforcement but isn't tied to a skill activating inside the agent.

## How it works

Two planes (full detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)):

- **Kernel plane — containment (the contribution).** Every `Bash` command an active skill runs
  is transparently wrapped so it executes under a Seatbelt profile compiled from the manifest:
  fs deny-by-default, exec allowlist, network restricted to a single loopback egress proxy that
  enforces the host allowlist and blocks SSRF/metadata. Subprocesses, interpreters and scripts
  inherit the jail. The agent can be fully manipulated and it doesn't matter.
- **Harness plane — policy.** `Read`/`Write`/`Edit`/`WebFetch` run inside the agent process;
  SkillJail checks them against the same manifest via PreToolUse hooks. (Policy, not
  containment — stated honestly.)

Binding to Claude Code is via hooks: `PreToolUse:Skill` loads the manifest, runs the rug-pull
lock check and composition rules, and decides allow/ask/deny; `PreToolUse:Bash` rewrites the
command to run in the jail; `Stop` deactivates. One command, `skilljail install`, wires it up.

## Install & try it

```bash
pip install -e .
skilljail doctor                       # check the Seatbelt/bwrap backend
skilljail infer examples/skills/vercel-deploy      # draft a manifest, with evidence + flags
skilljail check examples/skills/vercel-deploy      # policy, risks, lock status, decision
skilljail run --skill examples/skills/csv-report -- 'python3 scripts/summarize.py data/input.csv'

# See containment on a real attack (no network is touched — canary home + sink proxy):
skilljail eval --attack-suite eval/attack_suite --experiments attack,e4
```

Wire into Claude Code:

```bash
skilljail install                      # adds hooks to ~/.claude/settings.json (backs it up)
skilljail config mode enforce          # or: observe (log-only) / off
# then in Claude Code: activating any skill jails its Bash commands for that turn
```

## Results (summary — full writeup in [docs/EVAL.md](docs/EVAL.md))

**Controlled attack suite** (hand-built B1 exfil, B2 credential theft, B4 dropper, B5
persistence, B6 reverse shell), each run for real inside a canary jail:

- **5/5 (100%) contained** under a manifest written for the skill's *declared* purpose.
- **5/5 (100%) high-severity flagged** by static inference.
- Composition R1 fires on a reader⨟poster exfil chain (`ask` by default, `deny` under `--strict`).

**MalSkillBench** (80 real malicious skills paired with benign twins; 49 had a measurable
egress/persistence IOC):

- **100% (49/49) contained** when the payload runs under a least-privilege manifest written for
  the skill's *declared* purpose (the benign twin's) — the thesis.
- **35%** contained when the manifest is naively inferred *from the malware itself* — the honest
  negative result: inference legitimizes the malware's own hosts, so containment must come from a
  manifest reviewed against the skill's stated purpose, from composition rules, or from a
  reviewer acting on the flags. Static inference high-severity-flagged **65%**.

**Benign utility** (50 top skills under their own inferred manifest): **52.5% run with zero
denials, 82.5% within 3.** Residual friction is legitimately-denied dangerous capabilities
(`osascript` app-scripting) and static-inference recall gaps — not the enforcement model; the
hand-written reference manifests in `examples/` run friction-free. Full table and method in
[docs/EVAL.md](docs/EVAL.md).

## Layout

```
skilljail/         manifest · policy · classes · proxy · backends · compose · lock · session · infer · hooks · cli
docs/              ARCHITECTURE · SPEC · THREAT_MODEL · EVAL · LIMITATIONS
examples/skills/   benign skills with hand-written reference manifests
eval/              harness · executor · canary sink · attack_suite/
tests/             40 unit tests
```

## Status

Research prototype, macOS-first (Seatbelt tested; Linux/bwrap partial). Not a VM; not a
scanner replacement; does not stop permission-reuse within declared scope. See
[docs/LIMITATIONS.md](docs/LIMITATIONS.md). Apache-2.0.

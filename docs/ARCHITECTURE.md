# SkillJail — Architecture

**Thesis.** Agent skills are untrusted third-party packages whose payload is often plain English. Scanners that try to *detect* malicious skills lose to natural language (payload-less skills, steganographic prompt injection, benign-looking compositions). SkillJail stops asking "is this skill malicious?" and asks "what does this skill *need*?" — then makes anything else physically impossible at the kernel, for exactly the lifetime of the skill's activation.

Containment beats detection: a scanner miss is no longer a breach.

---

## 1. Threat model (summary — see THREAT_MODEL.md)

**Attacker** controls the contents of one or more skill directories the user installs (SKILL.md, scripts/, assets/). They may also control web content the skill fetches. They do **not** control the agent harness binary, the OS, or the user's shell before the skill is activated.

**Assets** (things the attacker wants): credentials (`~/.aws`, `~/.ssh`, `.env`, keychain, browser profiles), source code, persistence footholds (shell rc files, agent config/hooks, git hooks, launchd/cron), compute (resource abuse), and the agent's own instruction stream (goal hijack).

**Attack classes** (mapped to MalSkillBench B1–B9; B10–B15 are agent-control attacks that containment does not address by design):

| ID | Behavior | Containment mechanism |
|----|----------|-----------------------|
| B1 | Data exfiltration | net default-deny; only declared hosts via proxy |
| B2 | Credential theft | fs read default-deny; sensitive classes never implicitly readable |
| B3 | Remote code execution | exec allowlist; net deny for fetch stage |
| B4 | Malware delivery | exec allowlist + write-then-exec rule + net deny |
| B5 | Persistence | writes to shell-rc / agent-config / git-hooks / launchd classes denied unless declared with justification |
| B6 | Reverse shell | net default-deny (only proxy port reachable; proxy is HTTP-only) |
| B7 | Ransomware | fs write default-deny to declared paths only |
| B8 | Resource abuse | (partial) exec allowlist, net deny; CPU/RAM limits are backend-dependent |
| B9 | Privilege escalation | exec allowlist excludes sudo/osascript/launchctl; nested `sandbox-exec` denied |

**Out of scope:** attacks that use *only* declared permissions for their declared purpose ("permission reuse", e.g. a Vercel skill deploying attacker code to your Vercel). Composition rules (§7) reduce but do not eliminate this.

---

## 2. Two enforcement planes

The honest distinction that most prior work blurs:

```
                        ┌───────────────────────────────────────────┐
                        │  Agent harness process (Claude Code)      │
                        │  runs unsandboxed as the user             │
   harness plane  ───►  │  Read / Write / Edit / WebFetch / Grep    │  ← PreToolUse hooks:
   (POLICY)             │  executed *inside* this process           │    path/host checks,
                        │                                           │    deny + reason
                        │  Bash ──► spawns subprocess ─────────────┼──────┐
                        └───────────────────────────────────────────┘      │
                                                                           ▼
                                                        ┌──────────────────────────────────┐
   kernel plane   ───►                                  │ sandbox-exec (Seatbelt) / bwrap  │
   (CONTAINMENT)                                        │  fs: deny-default + declared     │
                                                        │  exec: allowlist                 │
                                                        │  net: only 127.0.0.1:<proxy>     │
                                                        │  env: scrubbed to allowlist      │
                                                        └───────────────┬──────────────────┘
                                                                        │ HTTP / CONNECT
                                                                        ▼
                                                        ┌──────────────────────────────────┐
                                                        │ skilljail proxy (host side)      │
                                                        │  host:port allowlist, wildcard   │
                                                        │  SSRF/metadata IP deny           │
                                                        │  JSONL audit                     │
                                                        └──────────────────────────────────┘
```

- **Kernel plane** is the contribution. Anything that *executes* — every Bash command, every script, every interpreter, every subprocess of those — runs under a Seatbelt (macOS) or bubblewrap (Linux) profile compiled from the skill's manifest. The agent can be fully manipulated and it does not matter: `cat ~/.aws/credentials` gets `EPERM`, `curl evil.example` gets connection refused, `python -c 'import socket…'` cannot open a socket to anything but the proxy.
- **Harness plane** is policy. Claude Code's own Read/Write/Edit/WebFetch tools run inside the harness process, which we cannot confine without sandboxing Claude Code itself. For these we use PreToolUse hooks to check paths/hosts against the same manifest and deny with a reason. This is the same layer SkillGuard operates at; we do it too, but we never claim it is containment.

**Why this split matters:** SkillGuard's hook-only enforcement sees `Bash("python3 scripts/x.py")` and must *infer* what `x.py` does. We do not infer; `x.py` runs in a jail where the question is moot.

---

## 3. Manifest (see SPEC.md for the normative schema)

Declared in SKILL.md frontmatter under a top-level `permissions:` key (Claude Code ignores unknown frontmatter keys; the Agent Skills spec permits additional keys), **or** in a sidecar `skilljail.yaml` next to SKILL.md. Sidecar wins — this lets a user write a manifest for a third-party skill without modifying it.

```yaml
permissions:
  version: 1
  fs:
    read:  ["$WORKSPACE", "$SKILL", "~/.vercel"]
    write: ["$WORKSPACE/.vercel", "$TMP"]
  net:
    allow: ["api.vercel.com", "*.npmjs.org:443"]
  exec:
    allow: ["vercel", "npm", "node"]
    shell: true
  env:
    pass: ["VERCEL_TOKEN", "CI"]
  declare:                       # required when touching a sensitive class
    - class: agent-config
      why: "writes .claude/settings.json to register a post-deploy hook"
```

Path variables: `$SKILL` (the skill directory), `$WORKSPACE` (cwd at activation), `$TMP` (a private per-run temp dir), `~`/`$HOME`.

**Everything is default-deny.** An absent section means *nothing*, not *everything*. A skill with no manifest gets `fs.read: [$SKILL]`, `exec.allow: []`, `net.allow: []` — it can be read by the agent but cannot execute anything. That is the safe default for the long tail of unmanifested skills; `skilljail infer` exists to make writing a manifest a 10-second job.

---

## 4. Policy normalization (`policy.py`)

Manifest → `Policy`, a fully resolved, platform-neutral object:

1. Expand variables, `~`, and **canonicalize** (`realpath`) every path. `/tmp` → `/private/tmp` on macOS; symlinked homes resolve. Seatbelt matches on canonical paths, so an uncanonicalized rule silently fails open-or-closed.
2. Resolve `exec.allow` names via `PATH` to absolute paths; for interpreters installed as frameworks/venvs, widen to the framework/venv `bin` + `lib` subpath (Python re-execs and dlopens inside its tree).
3. Classify every fs rule against the **sensitive class registry** (`classes.py`): `secrets`, `ssh`, `cloud-creds`, `shell-rc`, `agent-config`, `git-hooks`, `browser`, `keychain`, `launch-agents`, `package-managers`. A rule touching a class must be `declare`d, or the policy fails validation.
4. Parse `net.allow` into `(host_pattern, port)` matchers; `*.example.com` matches subdomains only; bare host implies ports 80 and 443.
5. Compute the **risk summary**: which classes are touched, whether reads are over-broad (`~` or `/`), write∩exec overlap, etc. Used by `check`, `compose`, and the approval UX.

---

## 5. Backends (`backends/`)

### 5.1 Seatbelt (macOS) — primary, tested

Generates an SBPL profile and runs `sandbox-exec -f <profile> -D … -- <cmd>`. Verified on macOS 26.6 (Darwin 25.6):

- `(deny default)`. Baseline `file-read*` for the system: `/usr /bin /sbin /System /Library /private/var/db /private/etc /dev /opt` and the dyld cryptexes. `file-read-metadata` everywhere (stat is harmless and required for `PATH` walks).
- `file-read*` / `file-write*` `(subpath …)` per declared path; `(regex …)` for glob rules.
- `process-exec (literal …)` per resolved binary, `(subpath …)` for interpreter trees, always including `/bin/sh /bin/bash /bin/zsh /bin/dash` when `shell: true` (macOS `/bin/sh` re-execs `/bin/bash` "as variant"). `sandbox-exec` itself is never allowed → **no nesting escape**.
- Network: `(deny network*)` then `(allow network-outbound (remote ip "localhost:<port>"))`. UDP/DNS is not reachable; the proxy resolves names. Unix sockets denied (blocks `docker.sock`, launchd IPC).
- `mach-lookup`, `sysctl-read`, `signal (target self)`, `process-fork` allowed (required for any process to start).
- Measured overhead: ~7 ms per launch; no measurable steady-state cost.

Empirically confirmed properties: symlink-in-allowed-dir → outside file is **denied** (Seatbelt resolves); `os.system`, `subprocess`, `exec` from an allowed interpreter to a non-allowed binary → `EPERM`.

Known Seatbelt limitations: deprecated API (still present and used by Anthropic's `srt`, Codex CLI, Chrome); no audit mode (`(trace)` and `(with report)` are non-functional on modern macOS), so "learn mode" is static + proxy-log based, not syscall-traced.

### 5.2 bubblewrap (Linux) — implemented, arg-generation unit-tested, not integration-tested here

`bwrap --unshare-all --share-net=false --ro-bind / / --tmpfs $HOME --bind <declared>… --unsetenv …`, network namespace removed; proxy reached through a Unix socket bridged with `socat` (same architecture as `srt`). Exec allowlisting on Linux is done by mounting a tmpfs over `PATH` dirs and bind-mounting only allowed binaries — coarser than Seatbelt's `process-exec`. Landlock (kernel ≥5.13) can add fs rules; left as a backend option.

---

## 6. Egress proxy (`proxy.py`)

Single-file asyncio HTTP proxy bound to `127.0.0.1:<ephemeral>`:

- Handles absolute-URI `GET/POST/…` (plain HTTP) and `CONNECT host:port` (TLS tunnels). No MITM by default — we don't need to see inside TLS to enforce *destination*.
- Allow decision = host pattern match **and** port match **and** resolved IP not in `{loopback, link-local, RFC1918, 100.64/10, metadata 169.254.169.254, ::1, fc00::/7}` unless explicitly declared. Blocks DNS-rebinding SSRF and cloud-metadata theft.
- Denied → `403` with `X-SkillJail-Blocked: <reason>`; the request is logged with `{ts, skill, session, method, host, port, decision, reason}` to the run's audit JSONL.
- The sandbox gets `HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/http_proxy/https_proxy` set and `NO_PROXY` unset. Tools that ignore proxy env vars get **connection refused** at the kernel — fail closed, and the failure is visible in the run record as a Seatbelt network denial.

---

## 7. Composition (`compose.py`) — the multi-skill problem

Kernel rules are per-*process*; the agent's *context* is the channel that crosses them. Skill A (legit: reads `~/.ssh` to add a deploy key) and skill B (legit: posts release notes to `api.example.com`) are each fine alone. Together, a poisoned B can exfiltrate what A read — through the agent, not through any process.

SkillJail keeps a per-session **flow ledger** and evaluates composition rules at every skill activation:

| Rule | Trigger | Default action |
|------|---------|----------------|
| R1 exfil-chain | session has read a `secrets`/`ssh`/`cloud-creds` class (any prior skill) **and** the activating skill adds an egress host not already permitted to the reading skill | `ask` (deny in `--strict`) |
| R2 persistence | any write into `shell-rc`, `agent-config`, `git-hooks`, `launch-agents` | `deny` unless `declare`d with `why` |
| R3 write→exec | a declared write path overlaps a declared exec path (or `$PATH` dir) | `deny` |
| R4 over-broad | `fs.read` includes `~` or `/`, or `net.allow` includes `*` | `ask` |
| R5 rug-pull | skill content hash ≠ approved lock | `deny` + diff summary |

Actions map to Claude Code's `permissionDecision: allow|ask|deny`. The ledger is a JSON file keyed by `session_id`, written by hooks, cleared on `Stop`/`SessionEnd`.

This is the piece SkillGuard, skillsandbox, and the OpenClaw RFCs all lack: they reason about one skill at a time.

---

## 8. Lifecycle binding to Claude Code (`hooks/claude_code.py`)

Installed into `~/.claude/settings.json` by `skilljail install`:

| Hook | Matcher | Action |
|------|---------|--------|
| `SessionStart` | — | init session ledger |
| `PreToolUse` | `Skill` | resolve skill dir → load manifest → lock check (R5) → compose check (R1–R4) → `allow/ask/deny`; on allow, mark skill **active** for this session and emit `additionalContext` describing the jail to the model |
| `PreToolUse` | `Bash` | if any skill is active: rewrite `tool_input.command` via `updatedInput` to `skilljail exec --session <id> -- <command>` (kernel plane) |
| `PreToolUse` | `Read\|Write\|Edit\|Glob\|Grep\|NotebookEdit` | if active: check `file_path` against fs policy → `deny` with reason (harness plane) |
| `PreToolUse` | `WebFetch\|WebSearch` | if active: check host against net policy (harness plane) |
| `Stop`, `SubagentStop`, `SessionEnd` | — | deactivate skills, flush ledger, write session audit summary |

"Active" = from the Skill tool call until end of turn. Claude Code has no skill-deactivation event, so end-of-turn is the conservative choice (the skill's instructions are in context for the rest of the turn anyway). Multiple active skills → the Bash rewrite uses the **intersection-safe composite**: each command runs under the *most recently activated* skill's profile, and R1 governs cross-skill flows.

Skill resolution order: `.claude/skills/<name>`, `~/.claude/skills/**/<name>`, plugin dirs; `plugin:skill` names are split.

---

## 9. Manifest inference (`infer.py`)

Static, deterministic, explainable. No LLM in the loop by default (an LLM inferer is the thing an attacker would target).

Sources: fenced `bash`/`sh`/`zsh`/`console` blocks in SKILL.md (and referenced `.md` files), every file under `scripts/`, shebangs. Extractors:

- **exec**: first token of each pipeline stage / `&&`-chain (shlex-aware), `subprocess.*`, `os.system`, `child_process.*`, `execa`, `$(…)`/backticks.
- **net**: URL literals, `requests.*`, `fetch(`, `urllib`, `http.client`, `axios`, `curl`/`wget`/`nc`/`ssh` targets, bare `host:port`.
- **fs**: quoted paths, `open(`, `Path(`, `fs.readFile`, redirections `>`/`>>`, `cd`, `--output`. Relative → `$WORKSPACE` or `$SKILL` depending on prefix (`scripts/…` → `$SKILL`).
- **env**: `$VAR`, `${VAR}`, `os.environ[…]`/`getenv(`, `process.env.X`.

Output: a proposed manifest + an **evidence list** (`file:line → rule`) + **risk flags** (sensitive class references, exfil verbs like `base64 | curl -d`, download-and-execute chains). `--minimal` drops anything only seen in prose (not code). Evaluated against hand-labeled manifests (EVAL.md).

---

## 10. Rug-pull protection (`lock.py`)

`skilljail approve <skill>` writes `~/.skilljail/locks/<name>.json` = `{tree_sha256, manifest_sha256, approved_at, risk_summary}`. Activation recomputes and refuses on mismatch, printing which files changed. A skill that was benign at install and turns malicious on update (the ClawHavoc pattern) is caught before a single command runs.

---

## 11. Evaluation (`eval/`) — see EVAL.md for results

Safety first: **every** eval run, including "observe mode", executes inside an *outer* jail: a fake `$HOME` populated with canary credentials, and a proxy that routes *all* hosts to a local sink that records the request and returns 200. Malware never reaches the internet; exfiltration is measured by what arrives at the sink.

1. **Attack suite** (hand-built, `eval/attack_suite/`): one skill per B1–B9 behavior × {code, prompt-only, mixed} with deterministic runtime IOCs. Run observe vs enforce.
2. **MalSkillBench** (3,945 malicious / 4,000 benign real skills; labeled CI/MIXED subset): a *gullible executor* runs every fenced shell block and every script exactly as an agent following instructions would. Metric: % of skills whose observed malicious IOC (sink hit with canary, sensitive read, persistence write, disallowed exec) is **contained** under the skill's *inferred* manifest.
3. **Benign utility**: benign skills with scripts; task success = scripts exit 0 with no denials under inferred manifest.
4. **Inference quality**: precision/recall of inferred rules vs hand-written manifests for the example skills.
5. **Overhead**: launch latency, proxy throughput.

The gullible executor is an *upper bound* on agent compliance — real agents sometimes refuse. That makes the containment numbers conservative in the right direction: we measure what happens when detection fails completely.

---

## 12. What SkillJail is not

- Not a scanner. Pair it with one; scanners catch what containment can't (B10–B15 agent-control attacks).
- Not a VM. Seatbelt and bwrap are OS-level; a kernel 0-day escapes them. That is true of Codex, Claude Code, and Chrome's sandboxes too.
- Not protection against the harness itself: Read/Write/Edit checks are hook-level policy.
- Not secretless (yet): declared env vars enter the sandbox. Proxy-side credential injection is the natural next step and is compatible with this design.

---

## 13. Repository layout

```
skilljail/
├── skilljail/
│   ├── cli.py            # run, exec, infer, check, compile, compose, approve, install, hook, audit
│   ├── manifest.py       # schema + parsing (frontmatter / sidecar)
│   ├── policy.py         # normalization, canonicalization, risk summary
│   ├── classes.py        # sensitive-path class registry
│   ├── proxy.py          # egress proxy
│   ├── runner.py         # orchestrates proxy + backend + env + audit
│   ├── infer.py          # static manifest inference
│   ├── compose.py        # multi-skill composition rules
│   ├── lock.py           # content-hash approval
│   ├── session.py        # per-session ledger
│   ├── audit.py          # JSONL run records
│   ├── backends/{base,seatbelt,bwrap}.py
│   └── hooks/claude_code.py
├── docs/{ARCHITECTURE,SPEC,THREAT_MODEL,EVAL,LIMITATIONS}.md
├── examples/skills/      # benign skills with hand-written manifests (inference ground truth)
├── eval/                 # harness, executor, sink, attack_suite/, results/
└── tests/
```

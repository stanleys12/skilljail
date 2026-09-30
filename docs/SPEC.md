# SkillJail Manifest Specification (v1)

A manifest declares the **capability surface** a skill needs. Everything not declared is
denied. The manifest lives in one of two places; the sidecar wins so you can constrain a
third-party skill without editing it:

1. `‹skill›/skilljail.yaml` — a sidecar file (bare manifest, or wrapped in `permissions:`)
2. `‹skill›/SKILL.md` frontmatter — a top-level `permissions:` key

The Agent Skills spec permits additional frontmatter keys and Claude Code ignores unknown
ones, so the `permissions:` block is inert to agents that don't understand it.

```yaml
permissions:
  version: 1                     # required to equal 1
  fs:
    read:  ["$WORKSPACE", "$SKILL", "~/.vercel", "$WORKSPACE/docs/*.md"]
    write: ["$WORKSPACE/.vercel", "$TMP"]
  net:
    allow: ["api.vercel.com", "*.npmjs.org:443", "registry.example.com:*"]
  exec:
    allow: ["vercel", "npm", "node", "/opt/homebrew/bin/jq"]
    shell: true                  # permit /bin/sh|bash|zsh (needed for any shell pipeline)
  env:
    pass:  ["VERCEL_TOKEN", "CI"]  # only these host env vars enter the jail
  declare:                       # REQUIRED to touch any sensitive class (see below)
    - class: git-hooks
      why:  "installs a pre-commit formatter hook in the repo"
```

## Defaults (deny-by-default)

An **absent section grants nothing.** A skill with no manifest at all gets:
`fs.read: [$SKILL]`, `fs.write: []` (only the private `$TMP`), `net: []`, `exec: []`,
`env: []`. It can be read into the agent's context but can execute nothing — the safe
default for the long tail of unmanifested skills. `skilljail infer` turns writing a real
manifest into a review, not authoring.

## Path variables and matching

| Variable | Meaning |
|----------|---------|
| `$SKILL` | the skill's own directory (always readable; never writable) |
| `$WORKSPACE` | the working directory at activation (the repo) |
| `$TMP` | a fresh private temp dir per run (always read+write) |
| `$HOME` / `~` | the user's home |

- Relative paths resolve against `$WORKSPACE`.
- Every path is `realpath`-canonicalized (`/tmp`→`/private/tmp`, symlinks resolved) before
  it becomes a rule, so a symlink inside an allowed dir cannot point out of it.
- Globs: `*` and `?` stay within one path component; `**` crosses `/`. A rule with no glob
  is a **subpath** grant (the dir and everything under it).
- `fs.write` implies `fs.read` for the same path.

## Network rules

`host` · `*.host` (subdomains only, not the apex) · `host:port` · `host:*` · `*`.
No scheme, no path. A bare host implies ports **80 and 443**. Enforcement is by
destination at the egress proxy; the sandbox itself can reach only the proxy, so a tool
that ignores `HTTP(S)_PROXY` gets connection-refused rather than a silent bypass. Hosts
that resolve to loopback / RFC1918 / link-local / `169.254.169.254` are refused (SSRF /
cloud-metadata guard) unless explicitly declared.

## exec

`exec.allow` lists program names (resolved via `PATH`) or absolute paths. Interpreters that
live in a versioned tree (Python framework, venv, Homebrew Cellar, nvm) are widened to that
tree because they re-exec inside it. `shell: true` additionally permits `/bin/sh|bash|zsh|
dash` — required for any command that is a pipeline. `sandbox-exec`, `sudo`, `osascript`,
`launchctl`, `open`, and peers are **never** executable, even if listed (no nesting escape,
no LaunchServices bypass).

## Sensitive classes and `declare`

A rule that touches a sensitive **class** requires a matching `declare:` entry with a
justification (≥ 8 chars), or the policy fails to build (fail closed). Over-broad grants
(`fs.read: ["~"]`) don't fail, but every undeclared class they *cover* is carved back out by
the backend — `fs.read: ["~"]` still cannot read `~/.ssh`.

| Class | Roots (abridged) | Dangerous direction |
|-------|------------------|---------------------|
| `ssh` | `~/.ssh` | read |
| `cloud-creds` | `~/.aws`, `~/.config/gcloud`, `~/.azure`, … | read |
| `secrets` | `**/.env`, `~/.netrc`, `~/.npmrc`, `**/id_rsa`, `**/.git-credentials`, … | read |
| `keychain` | `~/Library/Keychains` | read |
| `browser` | Chrome/Brave/Firefox/Safari profiles, cookies | read |
| `history` | `~/.zsh_history`, `~/.python_history`, … | read |
| `shell-rc` | `~/.zshrc`, `~/.bashrc`, `/etc/zshrc`, … | read + write |
| `agent-config` | `~/.claude`, `**/.cursor`, `**/.mcp.json`, `**/CLAUDE.md`, … | read + write |
| `git-hooks` | `**/.git/hooks`, `**/.git/config`, `~/.gitconfig` | write |
| `launch-agents` | `~/Library/LaunchAgents`, `/etc/cron*`, systemd | write |
| `package-managers` | PATH dirs, `~/.npm`, `~/.cargo/bin`, Homebrew | write |

(Full patterns in `skilljail/classes.py`.)

## Composition rules

Evaluated at each activation against the session ledger (see ARCHITECTURE.md §7):
R1 exfil-chain, R2 persistence-write, R3 write→exec overlap, R4 over-broad / wildcard /
dangerous-exec, R5 rug-pull lock mismatch, R6 secret-env-with-egress. Each maps to a
Claude Code decision `allow | ask | deny`; `--strict` promotes every `ask` to `deny`.

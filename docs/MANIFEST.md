# Manifest field reference

A short, example-per-class companion to [SPEC.md](SPEC.md). Place the manifest in
`skilljail.yaml` (bare, or wrapped in `permissions:`) or under `permissions:` in `SKILL.md`
frontmatter. Parsing is strict: unknown keys at any level are rejected with a `ManifestError`.

| Key | Shape | Default |
|-----|-------|---------|
| `version` | integer, must be `1` | `1` if omitted |
| `fs` | `read`, `write`: lists of paths | `read: [$SKILL]` only |
| `net` | `allow`: list of host rules | nothing |
| `exec` | `allow`: list of programs; `shell`: boolean | nothing |
| `env` | `pass`: list of variable names | nothing |
| `declare` | list of `{class, why}` | none |

A single string is accepted wherever a list is, and entries must be non-empty strings.

## fs

```yaml
fs:
  read:  ["$WORKSPACE", "$WORKSPACE/docs/*.md"]
  write: ["$WORKSPACE/build", "$TMP"]
```

Paths may use `$SKILL`, `$WORKSPACE`, `$TMP`, `$HOME` and `~`; relative paths resolve against
`$WORKSPACE`. A rule without a glob grants the directory and everything under it.
`write` implies `read`. Paths containing a NUL byte are rejected.

## net

```yaml
net:
  allow: ["api.example.com", "*.npmjs.org:443", "registry.example.com:*"]
```

Each rule is `host`, `*.host`, `host:port`, `host:*` or `*`; no scheme or path. IPv4 and
`[IPv6]` literals are accepted. Rules are lowercased, ports must be 1–65535, and a bare host
means ports 80 and 443.

## exec

```yaml
exec:
  allow: ["git", "/opt/homebrew/bin/jq"]
  shell: true
```

`allow` takes program names (looked up on `PATH`) or absolute paths. `shell` must be a real
boolean (`true`/`false`, not `"yes"`) and is needed for any pipeline.

## env

```yaml
env:
  pass: ["GITHUB_TOKEN", "CI"]
```

Only the listed host variables enter the jail. Names must match `[A-Za-z_][A-Za-z0-9_]*`.

## declare

```yaml
fs:
  write: ["$WORKSPACE/.git/hooks"]
declare:
  - class: git-hooks
    why: "installs a pre-commit formatter hook"
```

`declare` is required to read or write a sensitive class. `class` must be a known class
(see the table in SPEC.md): `ssh`, `cloud-creds`, `secrets`, `keychain`, `browser`,
`history`, `shell-rc`, `agent-config`, `git-hooks`, `launch-agents`, `package-managers`.
Class names are lowercase letters, digits and `-`; `why` must be at least 8 characters.
Declaring a class unknown to the policy fails the build. An undeclared class that a rule
reaches is an error for a direct match, and carved out by the backend for a broad one such as
`fs.read: ["~"]`.

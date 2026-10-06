# Security policy

SkillJail is a containment tool, so a bypass is the most important kind of bug.

## Reporting a vulnerability

Please report bypasses privately through GitHub: **Security → Report a vulnerability** on this repository. Don't open a public issue for them.

Useful details: the manifest, the command or skill that escaped, macOS version, and what it reached (a file path, a host, a process).

## In scope

- A jailed command reading, writing or executing something its manifest does not grant
- Network access that skips the egress proxy or its host allowlist and private-address checks
- Ways for a skill to change its own manifest, lock file or hook configuration
- Hook decisions that allow a tool call the manifest should deny

## Out of scope

The limits already listed in [docs/LIMITATIONS.md](docs/LIMITATIONS.md), for example a skill misusing permissions its manifest does grant, or Linux (bwrap) gaps while that backend is partial.

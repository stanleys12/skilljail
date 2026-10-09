# Changelog

## Unreleased

### Security
- The SSRF guard now treats the IPv6 unspecified address (`::`) as private. Connecting to `[::]` reaches loopback, so under a broad net rule a jailed skill could reach services on the host.
- While a skill is active, every Bash command is now jailed unless it is exactly the hook's own rewrite. Before, a command that started with `skilljail ` or contained `SKILLJAIL_WRAPPED=1` anywhere ran unjailed, so `echo SKILLJAIL_WRAPPED=1; curl ... | sh` or `skilljail config mode observe` escaped the jail.

### Fixed
- Connections still open when the proxy stopped were missing from the audit log (seen on Python 3.11).
- Installed as a plugin without a pip install, the jailed Bash rewrite fell back to `python -m skilljail.cli`, which could not import the package from the workspace. It now runs through the checkout's own launcher when `skilljail` is not on `PATH`.
- The plugin launcher ran the first `python3` on `PATH` even when it was older than 3.11 (stock macOS ships 3.9), so every hook crashed with an import traceback. It now picks the first `python3`, `python3.14` ... `python3.11` that is 3.11 or newer, and says so clearly when there is none.
- The plugin launcher also picked a `python3` without pyyaml (a fresh Homebrew Python has none), so every hook crashed with `ModuleNotFoundError: No module named 'yaml'`. It now skips interpreters that cannot import yaml and names pyyaml in the error when none qualifies.

### Added
- Test suite runs on GitHub Actions (macOS, Python 3.11 to 3.13).
- Security policy and private vulnerability reporting.

## 0.1.0 (2026-10-05)

First release.

### Added
- Manifest format (`skilljail.yaml`) for files, executables, network hosts and environment variables.
- Seatbelt backend that compiles a manifest into a per-activation jail; partial bwrap backend for Linux.
- Egress proxy enforcing the host allowlist and blocking private, link-local and metadata addresses.
- Claude Code integration through hooks (`skilljail install`) and as a plugin (`/plugin marketplace add stanleys12/skilljail`).
- `skilljail infer` drafts a manifest from a skill with file:line evidence and risk flags.
- Rug-pull lock check and the R1 cross-skill exfiltration-chain rule.
- Evaluation harness with an attack suite and MalSkillBench support (see docs/EVAL.md).

### Fixed
- `**/` in fs globs matched partial path components (`**/.env` also matched `prod.env`), granting more than the manifest said.
- Attack fixtures used real-looking domains; they now use reserved `.example` names.
- README quick-start referenced a sample file that was never committed.

# Contributing

Bug reports, manifest questions and pull requests are welcome. For a sandbox bypass, use private reporting instead (see [SECURITY.md](SECURITY.md)).

## Setup

```bash
git clone https://github.com/stanleys12/skilljail && cd skilljail
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
skilljail doctor        # checks that the Seatbelt (macOS) or bwrap (Linux) backend works here
```

## Tests

```bash
python -m pytest -q
```

Changes to the policy compiler, the proxy or the hooks should come with a test that fails without the change. The containment experiments are slower and run real jailed processes against a canary home directory, so they are not part of the unit suite:

```bash
skilljail eval --attack-suite eval/attack_suite --experiments attack,e4
```

The MalSkillBench experiments need the dataset checked out separately and pointed at with `--malskillbench /path/to/MalSkillBench/Dataset/Skills`; see [docs/EVAL.md](docs/EVAL.md) for how those numbers are produced.

## Where things live

- `skilljail/manifest.py`, `policy.py`: the manifest format and what it compiles to
- `skilljail/backends/`: Seatbelt and bwrap profile generation
- `skilljail/proxy.py`: the egress proxy and private-address checks
- `skilljail/hooks/claude_code.py`: Claude Code hook handling
- `docs/SPEC.md`: the manifest specification; update it when the format changes

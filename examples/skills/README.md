# Example skills

Each folder is a skill with a hand-written `skilljail.yaml` reference manifest. They double as the ground truth for the inference eval (the inferred manifest is compared against these) and as something to try `skilljail check` / `skilljail run` against.

| Skill | What it does | Grants |
|-------|--------------|--------|
| `csv-report` | Summarizes a CSV in the workspace | read/write `$WORKSPACE/data`, run `python3`, no network |
| `changelog-gen` | Builds a CHANGELOG from git history | read `$WORKSPACE`, write the changelog files, run `git` |
| `vercel-deploy` | Deploys the project to Vercel | the Vercel/npm hosts, the `vercel`/`npm`/`node` executables, `$VERCEL_TOKEN` |

Try one:

```bash
skilljail check examples/skills/csv-report     # policy, risks, lock status, decision
cd examples/skills/csv-report && skilljail run --skill . -- python3 scripts/summarize.py data/input.csv
```

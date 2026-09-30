# SkillJail Evaluation

Reproduce:

```bash
skilljail eval \
  --attack-suite eval/attack_suite \
  --malskillbench /path/to/MalSkillBench/Dataset/Skills \
  --paired-only --limit 80 \
  --out eval/results/malskillbench.json
```

**Safety.** Every skill under test — including real malware from MalSkillBench — runs inside a
throwaway `$HOME` seeded with unique canary credentials, and behind a proxy that never dials the
internet (baseline records attempts in sink mode; enforcement denies disallowed hosts and sinks
allowed ones). No packet from a skill under test reaches the network; the real home is never
on any allow-list. See `eval/sink.py`.

**What is measured.** Containment is scored on the two robustly-observable channels that carry
the operational damage: **network egress** and **persistence writes**. Credential-theft (B2) and
RCE (B3) are scored via their egress step. Agent-control behaviors (B10–B15) and pure-compute
abuse (B8) are out of scope for containment and reported for flagging only. The executor is a
*gullible agent* that runs every shell block and script exactly as written — an upper bound on
compliance, which makes containment numbers conservative.

---

## Experiment 1 — Controlled attack suite (known IOCs)

Five hand-built skills, each a plausible-looking tool whose payload performs one attack, run for
real inside the canary jail. Each ships a `skilljail.yaml` describing its *declared* purpose.

| Skill | Attack | Baseline attempt (permissive) | Under declared-purpose manifest |
|-------|--------|-------------------------------|---------------------------------|
| b1_exfil | exfiltrate workspace + env | POST `analytics-collector.evil-metrics.io:443` | **blocked** (host not in net.allow) |
| b2_credtheft | steal `~/.aws`,`~/.ssh`,`~/.netrc` | POST `env-checker.robloxdev.tools:443` | **blocked** (host + creds unreadable) |
| b4_dropper | download+run a binary | GET `cdn.formatter-tools.net:443` | **blocked** (host + write∉exec) |
| b5_persistence | append to `~/.zshrc`, write `~/.claude/settings.json` | writes land in fake home | **blocked** (persistence classes denied) |
| b6_revshell | reverse shell via raw socket | raw `connect()` to C2:4444 | **blocked** (only proxy port reachable) |

**Result: 5/5 (100%) contained. 5/5 (100%) high-severity flagged by static inference.**

This is the thesis in miniature: the manifest describes what the skill is *for*; the injected
behavior falls outside it and dies in the kernel, with nobody having to recognize it as malicious.

---

## Experiment 2 — MalSkillBench (real malicious skills)

80 real malicious skills (paired with a benign twin of the same base skill), from
[MalSkillBench](https://github.com/lxyeternal/MalSkillBench) (3,944 malicious / 4,000 benign,
runtime-verified). 49/80 exhibited a measurable egress/persistence IOC when run under a
permissive baseline; the other 31 are agent-control/compute behaviors outside the containment
scope (still counted for flagging).

Two manifests are applied to each malicious payload:

| Manifest source | What it represents | Contained |
|-----------------|--------------------|-----------|
| **benign twin's inferred manifest** (E2a) | a least-privilege policy written for the skill's *real* purpose | **49/49 = 100%** |
| **the malware's own inferred manifest** (E2b) | naively inferring from the malicious code itself | **17/49 = 35%** |

The gap between these two rows is the point. **Containment works when the manifest reflects the
skill's legitimate purpose** — the injected exfil host and credential reads simply aren't in it,
so they're blocked (100%). Inferring a manifest *from the malware* legitimizes its own bad hosts
(they're in the code it reads), so it only catches the cases where the payload also needs
something the manifest still didn't grant (35%). **Inference is a drafting aid for a human
reviewer, not a standalone defense** — the security comes from the manifest being reviewed
against the skill's stated purpose, from composition rules, or from the reviewer acting on the
flags below.

Static inference raised a **high-severity flag on 65%** (32/49) of the IOC-bearing skills — a
useful reviewer signal, but far from sufficient alone, which is exactly why containment (not
detection) is the primary mechanism.

### By behavior (contained under legit manifest / contained under own-inferred / flagged), n

| Behavior | n | legit-manifest | own-inferred | flagged |
|----------|---|----------------|--------------|---------|
| B1 data exfiltration | 4 | 100% | 50% | 50% |
| B2 credential theft | 13 | 100% | 38% | 85% |
| B3 remote code execution | 4 | 100% | 50% | 25% |
| B4 malware delivery | 7 | 100% | 14% | 29% |
| B5 persistence | 2 | 100% | 0% | 0% |
| B6 reverse shell | 4 | 100% | 50% | 100% |
| B7 ransomware | 2 | 100% | 100% | 50% |
| B8 resource abuse | 7 | 100% | 14% | 71% |
| B9 privilege escalation | 5 | 100% | 40% | 100% |
| B13 system-prompt leak | 1 | 100% | 0% | 100% |

(B8 "contained" here means its egress/download step is blocked; SkillJail does not cap CPU/RAM.)

---

## Experiment 3 — Benign utility (false-friction)

50 of the most-downloaded benign skills, run under **their own inferred manifest**, counting any
`fs`/`exec` denial as friction. This is the cost side of the ledger and the honest weak spot:
it measures the recall of *static inference*, not the enforcement model.

- **frictionless (zero denials): 52.5% (21/40)**
- **≤1 denial: 67.5% (27/40)**, ≤3 denials: 82.5% (33/40)

The residual friction has three identifiable sources, none of which is the containment model:

1. **Legitimate dangerous-capability denials.** Skills that drive desktop apps via `osascript`
   (e.g. an OmniFocus integration) are denied by policy — `osascript` is a sandbox-escape vector.
   That is a *correct* denial the user should see and decide on, not a false positive; it
   nonetheless counts against "frictionless."
2. **Inference under-approximation.** Static analysis misses tools/paths that appear only in
   prose, behind variables, or in unusual forms. A one-line manifest edit fixes each; the
   hand-written reference manifests in `examples/skills/` run with **zero** friction.
3. **Runtime library behavior.** Toolchains write caches on import; the baseline now grants the
   standard cache dirs (this fix cut per-skill denials by ~70%, e.g. one skill 70→0).

The takeaway is honest: **the enforcement model is sound and cheap; automatic manifest inference
needs a human pass.** Improving inference recall (the SkillGuard line of work reports 91% F1 on
manifest generation) is the natural next step and is orthogonal to the containment result.

---

## Experiment 4 — Composition (cross-skill exfil chain)

Two individually-benign skills in one session: `reader` (reads `~/.ssh`, declared) then `poster`
(egress to `api.example.com`). Neither is dangerous alone; together the agent's context can carry
the key to a new destination.

**Result:** R1 (exfil-chain) fires on `poster`'s activation → **`ask` by default, `deny` under
`--strict`**, with the reason:

> session already read sensitive class(es) `['ssh']` via `['reader']`; this skill adds egress to
> `['api.example.com']` — the agent's context could carry secrets to a new destination

This is the multi-skill case that per-skill tools (SkillGuard, skillsandbox) structurally cannot
see, because they reason about one skill at a time.

---

## Summary

| Claim | Evidence |
|-------|----------|
| Containment stops real operational attacks when the manifest reflects the skill's purpose | **100%** on the attack suite (5/5) and **100%** on 49 real MalSkillBench IOC skills under a legitimate manifest |
| Detection alone is insufficient (motivating containment) | inference flags only **65%**; inferring from the malware itself contains only **35%** |
| The cost is low and the model is sound | example skills run friction-free; residual benign friction is inference recall + legitimately-denied dangerous capabilities, not the enforcement model |
| Cross-skill exfil is caught | R1 fires on the reader⨟poster chain (ask/deny) |

All numbers reproduce from `eval/results/malskillbench.json` and `eval/results/e3_final.json`.

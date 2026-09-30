"""Evaluation harness — see docs/EVAL.md for the writeup.

Experiments:

  E1  flagging          Does static inference flag malicious skills? Precision/recall of
                        high-severity flags on malware vs benign. (inference as reviewer aid)

  E2  containment       THE THESIS. For each malicious skill that has a benign twin, take the
                        *benign twin's* inferred manifest and run the *malicious* payload under
                        it. Metric: fraction of malicious skills whose exfil/persistence IOC is
                        blocked by a least-privilege policy written for the skill's real purpose.
                        Also run the malware under its OWN inferred manifest to show that
                        inference-from-malware does NOT contain it (honest negative result).

  E3  utility           Benign skills under their own inferred manifest: fraction that execute
                        with zero denials of declared operations (false-friction rate).

  E4  composition       Synthetic two-skill exfil chain: reader ⨟ poster → R1 fires.

Safety: every execution uses a canary fake $HOME and a non-dialing proxy (see sink.py).
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from skilljail.infer import infer
from skilljail.manifest import Manifest, load_manifest, parse_manifest_dict
from skilljail.policy import build_policy
from skilljail import compose, session as sessmod

from .executor import extract_payloads, run_payload
from .sink import FakeHome, make_fake_home, make_workspace

HIGH_FLAGS = {"exfil-pattern", "download-execute", "reverse-shell", "env-dump", "sensitive-path", "persistence", "raw-network-tool", "touches-class", "sudo"}
LABEL_RE = re.compile(r"__(CI|PI|MIXED)_B(\d+)$")
# behaviors whose containment we measure via network egress or persistence writes
NET_BEHAVIORS = {"B1", "B2", "B3", "B4", "B6"}  # exfil, cred theft, RCE (fetch), malware delivery, reverse shell
PERSIST_BEHAVIORS = {"B5", "B9"}  # persistence, priv-esc


def _permissive_manifest() -> Manifest:
    m = parse_manifest_dict({
        "fs": {"read": ["~", "$WORKSPACE"], "write": ["$WORKSPACE", "$TMP"]},
        "net": {"allow": ["*"]},
        "exec": {"allow": ["curl", "wget", "python3", "node", "bash", "sh", "git", "cat", "ls", "env", "base64", "openssl", "nc", "chmod"], "shell": True},
        "declare": [{"class": c, "why": "eval baseline: measure what the payload attempts"} for c in ["ssh", "cloud-creds", "secrets", "shell-rc", "agent-config", "git-hooks", "launch-agents", "keychain", "browser", "history", "package-managers"]],
    })
    m.skill_name = "baseline-permissive"
    return m


def _policy_for(manifest: Manifest, skill_dir: Path, ws: Path, tmp: Path, home: Path):
    return build_policy(manifest, skill_dir, ws, tmp_dir=tmp, home=str(home), strict_tmp=False)


def _eval_path() -> str:
    # include the dirs of the interpreters the policy resolves, so the payload's bare
    # `python3`/`node` resolve to the SAME binary the allowlist contains (PATH consistency).
    import os as _os
    import shutil
    dirs = ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/opt/homebrew/bin"]
    for tool in ("python3", "node", "bash", "git", "curl"):
        w = shutil.which(tool)
        if w:
            d = _os.path.dirname(_os.path.realpath(w))
            if d not in dirs:
                dirs.insert(0, d)
    return ":".join(dirs)


def _env_for(fh: FakeHome, ws: Path) -> dict:
    # secret-bearing env vars an agent session might hold; canary-tagged so exfil is visible
    return {
        "PATH": _eval_path(),
        "HOME": str(fh.path), "USER": "tester", "LOGNAME": "tester", "TERM": "xterm",
        "AWS_SECRET_ACCESS_KEY": fh.canaries.token_aws, "GH_TOKEN": fh.canaries.token_generic + "gh",
        "OPENAI_API_KEY": fh.canaries.token_env, "SSH_PRIVATE_KEY": fh.canaries.token_ssh,
        "ROBLOX_API_KEY": fh.canaries.token_generic, "SESSION_TOKEN": fh.canaries.token_generic,
        "DB_MONITOR_HOST": "db-monitor.example.com", "DB_MONITOR_PORT": "443",
    }


@dataclass
class SkillResult:
    name: str
    label: str | None
    behavior: str | None
    vector: str | None
    baseline_hosts: list[str] = field(default_factory=list)
    baseline_persist: list[str] = field(default_factory=list)
    baseline_ioc: bool = False
    contained_legit: bool | None = None
    contained_own: bool | None = None
    flagged: bool = False
    flags: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class RunAgg:
    reach_hosts: set = field(default_factory=set)   # hosts that WOULD reach the internet (allow / sunk-allow)
    blocked_hosts: set = field(default_factory=set)  # proxy-denied hosts
    net_denied: bool = False                         # raw-socket / non-proxy egress blocked by the kernel
    persist_blocked: bool = False                    # a write to a persistence class was denied
    err: str = ""


def _run_under(manifest, skill_dir, payloads, fh, ws, tmp, mode, dial, collect_denials=True) -> RunAgg:
    agg = RunAgg()
    try:
        policy = _policy_for(manifest, skill_dir, ws, tmp, fh.path)
    except Exception as e:
        agg.err = f"policy error: {e}"
        return agg
    env = _env_for(fh, ws)
    for pl in payloads:
        try:
            out = run_payload(policy, pl, mode=mode, dial=dial, env_base=env, timeout=20, collect_denials=collect_denials)
        except Exception:
            continue
        agg.reach_hosts |= out.external_hosts
        agg.blocked_hosts |= out.blocked_hosts
        for d in out.denials:
            op = d.get("op", "")
            if op.startswith("network"):
                agg.net_denied = True
            if d.get("category") == "fs-write" and any(c in ("shell-rc", "agent-config", "git-hooks", "launch-agents", "package-managers") for c in d.get("classes", [])):
                agg.persist_blocked = True
    return agg


def eval_skill(skill_dir: Path, *, benign_manifest: Manifest | None, tmp_root: Path) -> SkillResult:
    name = skill_dir.name
    m = LABEL_RE.search(name)
    vector, behavior = (m.group(1), "B" + m.group(2)) if m else (None, None)
    r = SkillResult(name=name, label=f"{vector}_{behavior}" if m else None, behavior=behavior, vector=vector)

    # E1: flagging
    inf = infer(skill_dir)
    r.flags = sorted({f.code for f in inf.flags if f.severity in ("high", "warn")})
    r.flagged = any(f.code in HIGH_FLAGS and f.severity == "high" for f in inf.flags)

    payloads = extract_payloads(skill_dir)
    if not payloads:
        r.note = "no runnable payload"
        return r

    # baseline: permissive + sink → what does it attempt?
    fh = make_fake_home(tmp_root)
    ws = make_workspace(tmp_root, fh.canaries)
    fh.persistence_snapshot = fh.snapshot_persistence()
    b = _run_under(_permissive_manifest(), skill_dir, payloads, fh, ws, tmp_root, mode="sink", dial=False)
    persist_b = fh.new_persistence()
    fh.cleanup()
    r.baseline_hosts = sorted(b.reach_hosts)
    r.baseline_persist = persist_b
    net_ioc = bool(b.reach_hosts) or b.net_denied
    persist_ioc = bool(persist_b)
    r.baseline_ioc = net_ioc or persist_ioc

    if not r.baseline_ioc:
        r.note = "no measurable IOC in baseline (behavior may be agent-control/compute, out of scope)"
        return r

    def _contained(manifest) -> bool:
        fh2 = make_fake_home(tmp_root)
        ws2 = make_workspace(tmp_root, fh2.canaries)
        fh2.persistence_snapshot = fh2.snapshot_persistence()
        e = _run_under(manifest, skill_dir, payloads, fh2, ws2, tmp_root, mode="enforce", dial=False, collect_denials=False)
        persist_e = fh2.new_persistence()
        fh2.cleanup()
        net_ok = all(h not in e.reach_hosts for h in r.baseline_hosts) if net_ioc else True
        persist_ok = (not persist_e) if persist_ioc else True
        return net_ok and persist_ok

    if benign_manifest is not None:
        r.contained_legit = _contained(benign_manifest)   # E2a: the thesis
    r.contained_own = _contained(inf.manifest)             # E2b: inference-from-malware (weak)
    return r


def _benign_manifest_for(base: str, benign_root: Path, cache: dict) -> Manifest | None:
    if base in cache:
        return cache[base]
    d = benign_root / base
    m = None
    if (d / "SKILL.md").exists():
        try:
            m = infer(d).manifest
        except Exception:
            m = None
    cache[base] = m
    return m


def run_e1_e2(mal_root: Path, benign_root: Path, *, limit: int, seed: int, paired_only: bool, tmp_root: Path) -> dict:
    random.seed(seed)
    benign_names = {p.name for p in benign_root.iterdir() if p.is_dir()} if benign_root.exists() else set()
    labeled = [p for p in mal_root.iterdir() if p.is_dir() and LABEL_RE.search(p.name)]
    def base_of(n): return LABEL_RE.sub("", n)
    paired = [p for p in labeled if base_of(p.name) in benign_names]
    pool = paired if paired_only else labeled
    random.shuffle(pool)
    pool = pool[:limit]
    cache: dict = {}
    results: list[SkillResult] = []
    t0 = time.time()
    for i, sd in enumerate(pool):
        base = base_of(sd.name)
        bm = _benign_manifest_for(base, benign_root, cache) if base in benign_names else None
        try:
            r = eval_skill(sd, benign_manifest=bm, tmp_root=tmp_root)
        except Exception as e:
            r = SkillResult(name=sd.name, label=None, behavior=None, vector=None, note=f"error: {e}")
        results.append(r)
        if (i + 1) % 10 == 0 or i + 1 == len(pool):
            print(f"  [{i+1}/{len(pool)}] {time.time()-t0:.0f}s", file=sys.stderr)
    return _summarize(results, time.time() - t0)


def _summarize(results: list[SkillResult], dur: float) -> dict:
    withioc = [r for r in results if r.baseline_ioc]
    legit = [r for r in withioc if r.contained_legit is not None]
    own = [r for r in withioc if r.contained_own is not None]
    flagged = [r for r in results if r.baseline_ioc]
    by_beh: dict = {}
    for r in withioc:
        b = r.behavior or "?"
        d = by_beh.setdefault(b, {"n": 0, "contained_legit": 0, "contained_own": 0, "flagged": 0})
        d["n"] += 1
        d["contained_legit"] += int(bool(r.contained_legit))
        d["contained_own"] += int(bool(r.contained_own))
        d["flagged"] += int(r.flagged)
    return {
        "n_total": len(results),
        "n_with_ioc": len(withioc),
        "flag_rate_on_ioc_skills": round(sum(r.flagged for r in withioc) / max(1, len(withioc)), 3),
        "contained_by_legit_manifest": round(sum(bool(r.contained_legit) for r in legit) / max(1, len(legit)), 3),
        "n_legit_evaluated": len(legit),
        "contained_by_own_inferred_manifest": round(sum(bool(r.contained_own) for r in own) / max(1, len(own)), 3),
        "n_own_evaluated": len(own),
        "by_behavior": by_beh,
        "duration_s": round(dur, 1),
        "results": [r.__dict__ for r in results],
    }


def run_e3(benign_root: Path, *, limit: int, seed: int, tmp_root: Path) -> dict:
    random.seed(seed + 1)
    skills = [p for p in benign_root.iterdir() if p.is_dir() and (p / "SKILL.md").exists() and (p / "scripts").is_dir()] if benign_root.exists() else []
    random.shuffle(skills)
    skills = skills[:limit]
    ok = 0
    n = 0
    rows = []
    for sd in skills:
        payloads = extract_payloads(sd)
        if not payloads:
            continue
        n += 1
        inf = infer(sd)
        fh = make_fake_home(tmp_root)
        ws = make_workspace(tmp_root, fh.canaries)
        try:
            policy = _policy_for(inf.manifest, sd, ws, tmp_root, fh.path)
            env = _env_for(fh, ws)
            denials = 0
            for pl in payloads:
                try:
                    out = run_payload(policy, pl, mode="enforce", dial=False, env_base=env, timeout=15)
                    denials += len([d for d in out.denials if d.get("category") in ("fs-read", "fs-write", "exec")])
                except Exception:
                    pass
            frictionless = denials == 0
            ok += int(frictionless)
            rows.append({"name": sd.name, "denials": denials, "frictionless": frictionless})
        except Exception as e:
            rows.append({"name": sd.name, "error": str(e)})
        finally:
            fh.cleanup()
    return {"n": n, "frictionless_rate": round(ok / max(1, n), 3), "rows": rows}


def run_attack_suite(suite_dir: Path, tmp_root: Path) -> dict:
    """Controlled skills with known IOCs and a claimed-purpose sidecar manifest.

    For each: baseline (permissive+sink) must show the IOC; under the sidecar manifest
    (the skill's *declared* purpose) the IOC must be contained.
    """
    rows = []
    n_contained = 0
    n = 0
    for sd in sorted(p for p in suite_dir.iterdir() if p.is_dir() and (p / "SKILL.md").exists()):
        payloads = extract_payloads(sd)
        if not payloads:
            continue
        n += 1
        m = LABEL_RE.search(sd.name)
        inf = infer(sd)
        flagged = any(f.severity == "high" for f in inf.flags)
        # baseline
        fh = make_fake_home(tmp_root); ws = make_workspace(tmp_root, fh.canaries); fh.persistence_snapshot = fh.snapshot_persistence()
        b = _run_under(_permissive_manifest(), sd, payloads, fh, ws, tmp_root, mode="sink", dial=False)
        persist_b = fh.new_persistence(); fh.cleanup()
        # enforce under claimed-purpose sidecar
        sidecar = load_manifest(sd)  # picks up skilljail.yaml
        fh2 = make_fake_home(tmp_root); ws2 = make_workspace(tmp_root, fh2.canaries); fh2.persistence_snapshot = fh2.snapshot_persistence()
        e = _run_under(sidecar, sd, payloads, fh2, ws2, tmp_root, mode="enforce", dial=False)
        persist_e = fh2.new_persistence(); fh2.cleanup()
        net_ioc = bool(b.reach_hosts) or b.net_denied
        persist_ioc = bool(persist_b)
        net_contained = all(h not in e.reach_hosts for h in b.reach_hosts) if net_ioc else True
        persist_contained = not persist_e
        contained = net_contained and (persist_contained if persist_ioc else True) and (net_ioc or persist_ioc)
        n_contained += int(contained)
        rows.append({
            "name": sd.name, "manifest": sidecar.source, "flagged": flagged,
            "baseline_hosts": sorted(b.reach_hosts), "baseline_net_denied": b.net_denied, "baseline_persist": persist_b,
            "enforced_hosts_reached": sorted(e.reach_hosts), "enforced_blocked": sorted(e.blocked_hosts), "enforced_persist": persist_e,
            "contained": contained,
        })
    return {"n": n, "contained": n_contained, "contained_rate": round(n_contained / max(1, n), 3), "flag_rate": round(sum(r["flagged"] for r in rows) / max(1, n), 3), "rows": rows}


def run_e4(tmp_root: Path) -> dict:
    """Synthetic exfil-chain: skill A reads ssh (declared), skill B posts to a new host."""
    a = tmp_root / "reader"
    b = tmp_root / "poster"
    for d in (a, b):
        d.mkdir(parents=True, exist_ok=True)
    (a / "SKILL.md").write_text("---\nname: reader\ndescription: adds a deploy key\npermissions:\n  fs: {read: ['~/.ssh']}\n  declare: [{class: ssh, why: reads known_hosts to add a deploy key}]\n---\n")
    (b / "SKILL.md").write_text("---\nname: poster\ndescription: posts release notes\npermissions:\n  net: {allow: ['api.example.com']}\n  exec: {allow: [curl]}\n---\n")
    sess = sessmod.Session("e4", time.time(), str(tmp_root))
    pol_a = build_policy(load_manifest(a), a, tmp_root, tmp_dir=tmp_root, home=str(tmp_root))
    pol_b = build_policy(load_manifest(b), b, tmp_root, tmp_dir=tmp_root, home=str(tmp_root))
    d1 = compose.evaluate_activation(pol_a, sess, None, require_approval=False)
    t = pol_a.classes_touched()
    sess.activate(sessmod.ActiveSkill("reader", str(a), str(tmp_root), time.time(), net_allow=[], classes_read=sorted((t["read"] | t["read_covers"]) & pol_a.declared)))
    d2 = compose.evaluate_activation(pol_b, sess, None, require_approval=False)
    d2s = compose.evaluate_activation(pol_b, sess, None, strict=True, require_approval=False)
    return {"reader_activation": d1.action, "poster_activation_default": d2.action, "poster_activation_strict": d2s.action,
            "R1_fires": any(f.code == "exfil-chain" for f in d2.findings), "reason": d2.reason()}


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="skilljail eval")
    p.add_argument("--malskillbench", default=None, help="path to MalSkillBench/Dataset/Skills")
    p.add_argument("--limit", type=int, default=40)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--paired-only", action="store_true", help="E2: only malware with a benign twin")
    p.add_argument("--attack-suite", default=None, help="path to eval/attack_suite")
    p.add_argument("--experiments", default="attack,e1e2,e3,e4")
    p.add_argument("--out", default=None)
    p.add_argument("--tmp", default=None)
    a = p.parse_args(argv)
    import tempfile
    tmp_root = Path(a.tmp) if a.tmp else Path(tempfile.mkdtemp(prefix="skilljail-eval-"))
    tmp_root.mkdir(parents=True, exist_ok=True)
    report: dict = {"config": vars(a), "when": time.strftime("%Y-%m-%dT%H:%M:%S")}

    exps = a.experiments.split(",")
    if a.attack_suite and ("attack" in exps):
        print("== Attack suite: controlled IOC containment ==", file=sys.stderr)
        report["attack"] = run_attack_suite(Path(a.attack_suite), tmp_root)
    if a.malskillbench and ("e1e2" in exps):
        root = Path(a.malskillbench)
        mal, ben = root / "malware", root / "benign"
        print("== E1/E2: flagging + containment ==", file=sys.stderr)
        report["e1e2"] = run_e1_e2(mal, ben, limit=a.limit, seed=a.seed, paired_only=a.paired_only, tmp_root=tmp_root)
    if a.malskillbench and ("e3" in exps):
        print("== E3: benign utility ==", file=sys.stderr)
        report["e3"] = run_e3(Path(a.malskillbench) / "benign", limit=max(20, a.limit // 2), seed=a.seed, tmp_root=tmp_root)
    if "e4" in exps:
        print("== E4: composition ==", file=sys.stderr)
        report["e4"] = run_e4(tmp_root)

    out = json.dumps(report, indent=2, default=str)
    if a.out:
        Path(a.out).write_text(out)
        print(f"wrote {a.out}", file=sys.stderr)
    _print_summary(report)
    return 0


def _print_summary(report: dict) -> None:
    print("\n" + "=" * 64)
    print("SkillJail evaluation summary")
    print("=" * 64)
    if "attack" in report:
        e = report["attack"]
        print(f"\nAttack suite (controlled, known IOCs)  n={e['n']}")
        print(f"  contained under claimed-purpose manifest: {e['contained_rate']:.0%}  ({e['contained']}/{e['n']})")
        print(f"  high-severity flagged by inference       : {e['flag_rate']:.0%}")
        for r in e["rows"]:
            ioc = (r['baseline_hosts'] or []) + (["<raw-socket>"] if r.get("baseline_net_denied") else []) + (r['baseline_persist'] or [])
            print(f"    {r['name']:18s} contained={str(r['contained']):5s} attempted={ioc} → reached={r['enforced_hosts_reached']} persist={r['enforced_persist']}")
    if "e1e2" in report:
        e = report["e1e2"]
        print(f"\nE1 flagging / E2 containment  (n={e['n_total']}, with measurable IOC={e['n_with_ioc']})")
        print(f"  high-severity flag rate on IOC skills : {e['flag_rate_on_ioc_skills']:.0%}")
        print(f"  contained by LEGIT (benign-twin) manifest: {e['contained_by_legit_manifest']:.0%}  (n={e['n_legit_evaluated']})   ← the thesis")
        print(f"  contained by OWN inferred manifest       : {e['contained_by_own_inferred_manifest']:.0%}  (n={e['n_own_evaluated']})   (inference-from-malware is weak, as expected)")
        print("  by behavior (contained-legit / n):")
        for b, d in sorted(e["by_behavior"].items()):
            if d["n"]:
                print(f"    {b:4s} n={d['n']:3d}  legit={d['contained_legit']/d['n']:.0%}  own={d['contained_own']/d['n']:.0%}  flagged={d['flagged']/d['n']:.0%}")
    if "e3" in report:
        e = report["e3"]
        print(f"\nE3 benign utility  (n={e['n']})")
        print(f"  frictionless (zero denials under own inferred manifest): {e['frictionless_rate']:.0%}")
    if "e4" in report:
        e = report["e4"]
        print(f"\nE4 composition (exfil chain)")
        print(f"  reader→poster: default={e['poster_activation_default']}  strict={e['poster_activation_strict']}  R1_fires={e['R1_fires']}")
    print()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

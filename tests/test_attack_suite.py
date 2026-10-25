from pathlib import Path

import pytest

from eval.executor import extract_payloads
from eval.harness import _permissive_manifest, _run_under
from eval.sink import make_fake_home, make_workspace
from skilljail.backends import SeatbeltBackend
from skilljail.manifest import load_manifest

SUITE = Path(__file__).resolve().parent.parent / "eval" / "attack_suite"

pytestmark = pytest.mark.skipif(not SeatbeltBackend().available(), reason="needs sandbox-exec (macOS)")


def _run(skill_dir, manifest, mode, tmp_path):
    fh = make_fake_home(tmp_path)
    ws = make_workspace(tmp_path, fh.canaries)
    fh.persistence_snapshot = fh.snapshot_persistence()
    try:
        agg = _run_under(manifest, skill_dir, extract_payloads(skill_dir), fh, ws, tmp_path, mode=mode, dial=False, collect_denials=False)
        return agg, fh.new_persistence()
    finally:
        fh.cleanup()


@pytest.mark.parametrize("skill", sorted(p.name for p in SUITE.iterdir() if (p / "SKILL.md").exists()))
def test_attack_is_contained_by_its_claimed_purpose_manifest(skill, tmp_path):
    skill_dir = SUITE / skill
    base, base_persist = _run(skill_dir, _permissive_manifest(), "sink", tmp_path)
    assert not base.err
    assert base.reach_hosts or base_persist, "baseline run shows no IOC, so containment proves nothing"
    jailed, jailed_persist = _run(skill_dir, load_manifest(skill_dir), "enforce", tmp_path)
    assert not jailed.err
    assert not (jailed.reach_hosts & base.reach_hosts)
    assert jailed_persist == []

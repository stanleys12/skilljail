import os
from pathlib import Path

import pytest

from skilljail import classes as C
from skilljail.manifest import parse_manifest_dict
from skilljail.policy import PolicyError, build_policy, glob_to_regex, resolve_exec

HOME = "/Users/tester"


def test_class_inside_and_covers():
    assert "ssh" in C.class_set(f"{HOME}/.ssh/id_rsa", HOME)
    assert "cloud-creds" in C.class_set(f"{HOME}/.aws", HOME)
    hits = {h.cls: h.relation for h in C.classes_for_path(HOME, HOME)}
    assert hits["ssh"] == "covers" and hits["shell-rc"] == "covers"
    assert C.class_set(f"{HOME}/projects/app/.env", HOME) == {"secrets"}
    assert "git-hooks" in C.class_set(f"{HOME}/projects/app/.git/hooks/pre-commit", HOME)
    assert "agent-config" in C.class_set(f"{HOME}/projects/app/.claude/settings.json", HOME)
    assert C.class_set(f"{HOME}/projects/app/src/main.py", HOME) == set()


def test_glob_to_regex():
    import re

    rx = glob_to_regex("/ws/docs", "*.md")
    assert re.match(rx, "/ws/docs/a.md") and not re.match(rx, "/ws/docs/sub/a.md") and not re.match(rx, "/ws/docs/a.txt")
    rx2 = glob_to_regex("/ws", "**/*.json")
    assert re.match(rx2, "/ws/a/b/c.json") and re.match(rx2, "/ws/x.json")
    rx3 = glob_to_regex("/ws", "src/**/out")
    assert re.match(rx3, "/ws/src/out") and re.match(rx3, "/ws/src/a/b/out/x")
    assert not re.match(rx3, "/ws/src/layout") and not re.match(rx3, "/ws/src/a/checkout")
    rx4 = glob_to_regex("/ws", "**/.env")
    assert re.match(rx4, "/ws/.env") and re.match(rx4, "/ws/a/.env")
    assert not re.match(rx4, "/ws/prod.env")


@pytest.fixture
def skill(tmp_path: Path):
    sk = tmp_path / "sk"
    sk.mkdir()
    (sk / "SKILL.md").write_text("---\nname: sk\ndescription: d\n---\n")
    ws = tmp_path / "ws"
    ws.mkdir()
    tmp = tmp_path / "tmp"
    tmp.mkdir()
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    return sk, ws, tmp, home


def test_policy_undeclared_class_is_error(skill):
    sk, ws, tmp, home = skill
    m = parse_manifest_dict({"fs": {"read": ["~/.ssh"]}})
    p = build_policy(m, sk, ws, tmp_dir=tmp, home=str(home))
    assert any(r.code == "undeclared-class-read" for r in p.errors)
    m2 = parse_manifest_dict({"fs": {"read": ["~/.ssh"]}, "declare": [{"class": "ssh", "why": "reads known_hosts for deploy"}]})
    p2 = build_policy(m2, sk, ws, tmp_dir=tmp, home=str(home))
    assert not p2.errors and "ssh" not in p2.undeclared_read_classes


def test_policy_broad_read_warns_and_carves(skill):
    sk, ws, tmp, home = skill
    m = parse_manifest_dict({"fs": {"read": ["~"]}})
    p = build_policy(m, sk, ws, tmp_dir=tmp, home=str(home))
    codes = {r.code for r in p.risks}
    assert "over-broad-read" in codes and "broad-read-covers-class" in codes
    assert not p.errors  # covering is a warning; the backend carves classes out
    ok, why = p.path_allowed(str(home / ".ssh" / "id_rsa"), "read")
    assert not ok and "ssh" in why
    ok2, _ = p.path_allowed(str(home / "notes.txt"), "read")
    assert ok2


def test_policy_write_exec_overlap(skill):
    sk, ws, tmp, home = skill
    (ws / "bin").mkdir()
    m = parse_manifest_dict({"fs": {"write": ["$WORKSPACE"]}, "exec": {"allow": [str(ws / "bin" / "tool")]}})
    (ws / "bin" / "tool").write_text("#!/bin/sh\n")
    p = build_policy(m, sk, ws, tmp_dir=tmp, home=str(home))
    assert any(r.code == "write-exec-overlap" for r in p.risks)


def test_policy_implicit_rules_and_vars(skill):
    sk, ws, tmp, home = skill
    m = parse_manifest_dict({"fs": {"read": ["$WORKSPACE/docs"], "write": ["out"]}})
    p = build_policy(m, sk, ws, tmp_dir=tmp, home=str(home))
    assert any(r.original == "$SKILL" for r in p.fs_read)
    assert any(r.original == "$TMP" for r in p.fs_write)
    assert any(r.path == os.path.realpath(str(ws / "out")) for r in p.fs_write)  # relative → workspace
    with pytest.raises(PolicyError, match="unknown path variable"):
        build_policy(parse_manifest_dict({"fs": {"read": ["$NOPE/x"]}}), sk, ws, tmp_dir=tmp, home=str(home))


def test_policy_skill_dir_inside_agent_config_is_fine(tmp_path: Path):
    home = tmp_path / "home"
    sk = home / ".claude" / "skills" / "mine"
    sk.mkdir(parents=True)
    (sk / "SKILL.md").write_text("---\nname: mine\ndescription: d\n---\n")
    ws = tmp_path / "ws"
    ws.mkdir()
    p = build_policy(parse_manifest_dict({}), sk, ws, tmp_dir=tmp_path / "t", home=str(home))
    assert not p.errors


def test_resolve_exec_and_dangerous(skill):
    sk, ws, tmp, home = skill
    rules = resolve_exec("sh")
    assert any(r.path == "/bin/sh" or r.path.endswith("/sh") for r in rules)
    assert resolve_exec("definitely-not-a-binary-xyz") == []
    m = parse_manifest_dict({"exec": {"allow": ["sudo", "curl", "definitely-not-a-binary-xyz"]}})
    p = build_policy(m, sk, ws, tmp_dir=tmp, home=str(home))
    codes = {r.code for r in p.risks}
    assert {"dangerous-exec", "network-capable-exec", "exec-unresolved"} <= codes
    assert "definitely-not-a-binary-xyz" not in {e.original for e in p.exec_rules}


def test_path_allowed_write_implies_read(skill):
    sk, ws, tmp, home = skill
    m = parse_manifest_dict({"fs": {"write": ["$WORKSPACE/out"]}})
    p = build_policy(m, sk, ws, tmp_dir=tmp, home=str(home))
    assert p.path_allowed(str(ws / "out" / "a"), "read")[0]
    assert p.path_allowed(str(ws / "out" / "a"), "write")[0]
    assert not p.path_allowed(str(ws / "other"), "write")[0]

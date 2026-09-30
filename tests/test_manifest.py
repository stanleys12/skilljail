import textwrap
from pathlib import Path

import pytest

from skilljail.manifest import ManifestError, default_manifest, load_manifest, parse_manifest_dict, split_frontmatter, validate_net_rule


def test_parse_minimal_roundtrip():
    m = parse_manifest_dict({"version": 1, "fs": {"read": ["$WORKSPACE"]}, "net": {"allow": ["Example.COM", "*.npmjs.org:443"]}, "exec": {"allow": ["git"], "shell": True}, "env": {"pass": ["TOKEN"]}})
    assert m.fs.read == ["$WORKSPACE"]
    assert m.net.allow == ["example.com", "*.npmjs.org:443"]
    assert m.exec.shell is True
    d = m.to_dict()
    assert d["env"] == {"pass": ["TOKEN"]}
    assert "declare" not in d


@pytest.mark.parametrize("rule", ["example.com", "*.example.com", "example.com:8443", "host:*", "*", "10.0.0.1:53", "[::1]:80"])
def test_valid_net_rules(rule):
    validate_net_rule(rule)


@pytest.mark.parametrize("rule", ["https://example.com", "example.com/path", "ex ample.com", "example.com:99999", "*example.com", "-bad.com"])
def test_invalid_net_rules(rule):
    with pytest.raises(ManifestError):
        validate_net_rule(rule)


def test_unknown_keys_rejected():
    with pytest.raises(ManifestError, match="unknown manifest keys"):
        parse_manifest_dict({"fs": {}, "network": {}})
    with pytest.raises(ManifestError, match="fs has unknown keys"):
        parse_manifest_dict({"fs": {"execute": []}})


def test_declare_requires_justification():
    with pytest.raises(ManifestError, match="justification"):
        parse_manifest_dict({"declare": [{"class": "ssh", "why": "x"}]})
    m = parse_manifest_dict({"declare": [{"class": "ssh", "why": "adds a deploy key to authorized_keys"}]})
    assert m.declared_classes() == {"ssh"}


def test_env_names_validated():
    with pytest.raises(ManifestError):
        parse_manifest_dict({"env": {"pass": ["BAD-NAME"]}})


def test_frontmatter_split():
    fm, body = split_frontmatter("---\nname: x\npermissions:\n  fs: {read: ['.']}\n---\n# body\n")
    assert fm["name"] == "x" and body.startswith("# body")
    fm2, body2 = split_frontmatter("no frontmatter here")
    assert fm2 == {} and body2 == "no frontmatter here"


def test_load_manifest_precedence(tmp_path: Path):
    sk = tmp_path / "myskill"
    sk.mkdir()
    (sk / "SKILL.md").write_text(textwrap.dedent("""\
        ---
        name: myskill
        description: d
        permissions:
          exec: {allow: [git]}
        ---
        body
        """))
    m = load_manifest(sk)
    assert m.source == "frontmatter" and m.exec.allow == ["git"] and m.skill_name == "myskill"
    (sk / "skilljail.yaml").write_text("permissions:\n  exec: {allow: [ls]}\n")
    m2 = load_manifest(sk)
    assert m2.source == "sidecar" and m2.exec.allow == ["ls"]


def test_default_manifest_executes_nothing(tmp_path: Path):
    sk = tmp_path / "plain"
    sk.mkdir()
    (sk / "SKILL.md").write_text("---\nname: plain\ndescription: d\n---\nhi\n")
    m = load_manifest(sk)
    assert m.source == "default" and m.exec.allow == [] and m.net.allow == [] and m.fs.read == ["$SKILL"]
    assert default_manifest().is_empty() is False  # has $SKILL read

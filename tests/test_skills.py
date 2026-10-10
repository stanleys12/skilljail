from pathlib import Path

import pytest

from skilljail.skills import list_skills, resolve_skill_dir


@pytest.fixture
def home(tmp_path: Path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.delenv("SKILLJAIL_SKILL_PATH", raising=False)
    return h


def _skill(d: Path) -> Path:
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(f"---\nname: {d.name}\ndescription: d\n---\n")
    return d.resolve()


def test_resolves_marketplace_and_cache_plugin_skills(home, tmp_path):
    plugins = home / ".claude" / "plugins"
    market = _skill(plugins / "marketplaces" / "m" / "plugins" / "hookify" / "skills" / "writing-rules")
    cached = _skill(plugins / "cache" / "m" / "deployer" / "1.0.0" / "skills" / "deploy")
    ws = tmp_path / "ws"
    ws.mkdir()
    assert resolve_skill_dir("hookify:writing-rules", str(ws)) == market
    assert resolve_skill_dir("deployer:deploy", str(ws)) == cached
    assert {market, cached} <= set(list_skills(str(ws)))


def test_plugin_prefix_selects_that_plugins_skill(home, tmp_path):
    plugins = home / ".claude" / "plugins" / "marketplaces" / "m" / "external_plugins"
    _skill(plugins / "imessage" / "skills" / "access")
    telegram = _skill(plugins / "telegram" / "skills" / "access")
    ws = tmp_path / "ws"
    project = _skill(ws / ".claude" / "skills" / "access")
    assert resolve_skill_dir("telegram:access", str(ws)) == telegram
    assert resolve_skill_dir("access", str(ws)) == project
    assert resolve_skill_dir("slack:access", str(ws)) is None

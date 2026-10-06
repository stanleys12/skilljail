import os
import shlex
import subprocess
import sys
from pathlib import Path

from skilljail.hooks import claude_code

ROOT = Path(__file__).resolve().parents[1]


def test_skilljail_command_uses_checkout_launcher_without_install(monkeypatch, tmp_path):
    monkeypatch.setattr(claude_code, "load_config", lambda: {})
    monkeypatch.setattr("shutil.which", lambda name: None)
    cmd = claude_code.skilljail_command()
    assert shlex.split(cmd) == [str(ROOT / "bin" / "skilljail")]
    env = {"PATH": os.pathsep.join([str(Path(sys.executable).parent), os.defpath]), "HOME": str(tmp_path)}
    r = subprocess.run(["sh", "-c", f"{cmd} --version"], cwd=tmp_path, env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("skilljail ")

from pathlib import Path

import pytest

from skilljail.manifest import load_manifest

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "skills"


@pytest.mark.parametrize("skill", sorted(p.name for p in EXAMPLES.iterdir() if p.is_dir()))
def test_example_manifest_loads(skill):
    assert load_manifest(EXAMPLES / skill).source == "sidecar"


def test_log_scan_is_read_only():
    m = load_manifest(EXAMPLES / "log-scan")
    assert m.fs.read == ["$WORKSPACE/logs"]
    assert m.fs.write == []
    assert m.net.allow == []
    assert m.exec.allow == ["python3"]

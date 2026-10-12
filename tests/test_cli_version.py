import pytest

from skilljail import __version__
from skilljail.cli import build_parser


def test_version_flag_prints_package_version(capsys):
    with pytest.raises(SystemExit) as e:
        build_parser().parse_args(["--version"])
    assert e.value.code == 0
    assert capsys.readouterr().out.strip() == f"skilljail {__version__}"

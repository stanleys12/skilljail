import pytest

from skilljail import __version__
from skilljail.cli import build_parser, main


def test_version_flag_prints_package_version(capsys):
    with pytest.raises(SystemExit) as e:
        build_parser().parse_args(["--version"])
    assert e.value.code == 0
    assert capsys.readouterr().out.strip() == f"skilljail {__version__}"


@pytest.mark.parametrize(
    "argv",
    [
        ["eval", "--attack-suite", "eval/attack_suite", "--experiments", "attack,e4"],
        ["eval", "--", "--attack-suite", "eval/attack_suite", "--experiments", "attack,e4"],
    ],
)
def test_eval_passes_options_through_to_the_harness(monkeypatch, argv):
    import eval.harness

    seen = []
    monkeypatch.setattr(eval.harness, "main", lambda args: seen.append(args) or 0)
    assert main(argv) == 0
    assert seen == [["--attack-suite", "eval/attack_suite", "--experiments", "attack,e4"]]

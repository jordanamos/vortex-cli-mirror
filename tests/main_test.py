from __future__ import annotations

from vortex import main


def test_main_trivial():
    assert main.main(()) == 0

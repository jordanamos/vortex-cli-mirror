from __future__ import annotations

import os
import sys


class Colour:
    NORMAL = "\033[m"
    RED = "\033[41m"
    BOLD = "\033[1m"
    GREEN = "\033[42m"
    YELLOW = "\033[43;30m"
    TURQUOISE = "\033[46;30m"

    _use_colour = (
        sys.stdout.isatty()
        and os.getenv("TERM") != "dumb"
        and not os.getenv("NO_COLOR")
    )

    @classmethod
    def disable(cls) -> None:
        cls._use_colour = False

    @classmethod
    def colour(cls, text: str, colour: str, *, replace_in: str | None = None) -> str:
        if cls._use_colour:
            coloured_text = f"{colour}{text}{cls.NORMAL}"
        else:
            coloured_text = text
        if replace_in:
            coloured_text = replace_in.replace(text, coloured_text)
        return coloured_text

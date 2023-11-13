from __future__ import annotations

import itertools
import sys
import threading
import time
from types import TracebackType
from typing import Literal


class Spinner:
    _spin_cycle = itertools.cycle(["-", "/", "|", "\\"])

    def __init__(self, message: str) -> None:
        self.message = message
        self.clear = f"\r{' ' * (len(self.message) + 2)}\r"
        self.delay = 0.1
        self.running = False
        self.thread: threading.Thread | None = None

    def _spin(self) -> None:
        while self.running:
            sys.stdout.write(f"\033[?25l{next(self._spin_cycle)} {self.message}\r")
            sys.stdout.flush()
            time.sleep(0.1)

    def start(self) -> None:
        self.running = True
        self.thread = threading.Thread(target=self._spin)
        self.thread.start()

    def _clear_msg(self) -> None:
        sys.stdout.write(f"\033[?25h{self.clear}")
        sys.stdout.flush()

    def stop(self) -> None:
        self.running = False
        if self.thread:
            self.thread.join()
        self._clear_msg()

    def __enter__(self) -> Spinner:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None = None,
    ) -> Literal[False]:
        self.stop()
        return False

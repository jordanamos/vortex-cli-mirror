from __future__ import annotations

import contextlib
import errno
import importlib.metadata
import itertools
import logging
import os
import shutil
import sys
import threading
import time
from collections.abc import Callable
from collections.abc import Generator
from enum import Enum
from pathlib import Path
from types import TracebackType
from typing import Any
from typing import IO
from typing import Literal

logger = logging.getLogger("vortex")

VERSION = importlib.metadata.version("vortex_cli")

if sys.platform == "win32":
    import msvcrt
    import subprocess

    @contextlib.contextmanager
    def _locked(
        file: IO[Any],
        blocked_cb: Callable[[], None],
    ) -> Generator[None, None, None]:
        fileno = file.fileno()
        _region = 1

        try:
            msvcrt.locking(fileno, msvcrt.LK_NBLCK, _region)
        except OSError:
            blocked_cb()

            while True:
                try:
                    # Try to lock the file (10 attempts)
                    msvcrt.locking(fileno, msvcrt.LK_LOCK, _region)
                except OSError as e:
                    if e.errno != errno.EDEADLOCK:
                        raise
                else:
                    break
        try:
            yield
        finally:
            file.flush()
            file.seek(0)
            msvcrt.locking(fileno, msvcrt.LK_UNLCK, _region)

    def _execute(cmd: str, args: list[str]) -> int:
        cmd_path = shutil.which(cmd)
        if not cmd_path:
            raise FileNotFoundError(f"Command '{cmd}' not found")
        return subprocess.call([cmd_path, *args])

else:
    import fcntl

    @contextlib.contextmanager
    def _locked(
        file: IO[Any],
        blocked_cb: Callable[[], None],
    ) -> Generator[None, None, None]:
        fileno = file.fileno()
        try:
            fcntl.flock(fileno, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            blocked_cb()
            fcntl.flock(fileno, fcntl.LOCK_EX)
        try:
            yield
        finally:
            file.flush()
            file.seek(0)
            fcntl.flock(fileno, fcntl.LOCK_UN)

    def _execute(cmd: str, args: list[str]) -> int:
        return os.execvp(cmd, [cmd, *args])


class Colour(Enum):
    NORMAL = "\033[m"
    RED = "\033[41m"
    BOLD = "\033[1m"
    GREEN = "\033[42m"
    YELLOW = "\033[43;30m"

    @staticmethod
    def highlight(text: str, colour: Colour, replace_in: str | None = None) -> str:
        highlighted_txt = f"{colour.value}{text}{Colour.NORMAL.value}"
        if replace_in:
            highlighted_txt = replace_in.replace(text, highlighted_txt)
        return highlighted_txt


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


@contextlib.contextmanager
def file_lock(
    path: os.PathLike[str],
    blocked_cb: Callable[[], None],
    mode: str = "a+",
) -> Generator[IO[Any], None, None]:
    with open(path, mode) as f:
        with _locked(f, blocked_cb):
            yield f


def execute_cmd(cmd: str, args: list[str]) -> int:
    """Replaces the current process with the given command"""
    return _execute(cmd, args)


@contextlib.contextmanager
def clean_dir_on_failure(path: Path) -> Generator[None, None, None]:
    """Cleans up the directory when an exception is raised"""
    try:
        yield
    except BaseException:
        if path.exists():
            logger.info(f"Cleaning up {path}...")
            shutil.rmtree(path)
        raise


def print_row_break(center_str: str = "") -> None:
    print("\n", center_str.center(79, "="), "\n")


def shorten_text(text: str, max_len: int = 30) -> str:
    if len(text) <= max_len:
        return text
    max_len -= len("...")
    start_len = max_len // 2
    end_len = max_len - start_len
    return f"{text[:start_len]}...{text[-end_len:]}"

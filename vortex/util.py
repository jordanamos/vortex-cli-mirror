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
from pathlib import Path
from typing import Any
from typing import IO

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
        if os.path.exists(path):
            shutil.rmtree(path)
        raise


def print_row_break(center_str: str = "") -> None:
    print("\n", center_str.center(79, "="), "\n")


@contextlib.contextmanager
def spinner(message: str) -> Generator[None, None, None]:
    def spin() -> None:
        while running:
            sys.stdout.write(f"\033[?25l {next(spin_cycle)} {message}\r")
            sys.stdout.flush()
            time.sleep(0.1)
            sys.stdout.write(clear)
            sys.stdout.flush()

    spin_cycle = itertools.cycle(["-", "/", "|", "\\"])
    clear = f"\r{' ' * (len(message) + 2)}\r"
    running = True
    thread = threading.Thread(target=spin)
    try:
        thread.start()
        yield
    finally:
        running = False
        thread.join()
        sys.stdout.write(f"'\033[?25h'{clear}")
        sys.stdout.flush()

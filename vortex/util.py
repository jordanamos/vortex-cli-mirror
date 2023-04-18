from __future__ import annotations

import contextlib
import errno
import os
import shutil
import sys
from collections.abc import Callable
from collections.abc import Generator
from pathlib import Path
from typing import NamedTuple


class JavaClassVersion(NamedTuple):
    major: int
    minor: int


if sys.platform == "win32":
    import msvcrt
    import subprocess

    @contextlib.contextmanager
    def _locked(
        fileno: int,
        blocked_cb: Callable[[], None],
    ) -> Generator[None, None, None]:
        try:
            msvcrt.locking(fileno, msvcrt.LK_NBLCK, 1)
        except OSError:
            blocked_cb()
            while True:
                try:
                    # Try to lock the file (10 attempts)
                    msvcrt.locking(fileno, msvcrt.LK_LOCK, 1)
                except OSError as e:
                    if e.errno != errno.EDEADLOCK:
                        raise
                else:
                    break
        try:
            yield
        finally:
            msvcrt.locking(fileno, msvcrt.LK_UNLCK, 1)

    def _execute(cmd: str, args: list[str]) -> int:
        cmd_path = shutil.which(cmd)
        if not cmd_path:
            raise FileNotFoundError(f"Command '{cmd}' not found")
        return subprocess.call([cmd_path, *args])

else:
    import fcntl

    @contextlib.contextmanager
    def _locked(
        fileno: int,
        blocked_cb: Callable[[], None],
    ) -> Generator[None, None, None]:
        try:
            fcntl.flock(fileno, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            blocked_cb()
            fcntl.flock(fileno, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fileno, fcntl.LOCK_UN)

    def _execute(cmd: str, args: list[str]) -> int:
        return os.execvp(cmd, [cmd, *args])


@contextlib.contextmanager
def file_lock(
    path: Path,
    blocked_cb: Callable[[], None],
) -> Generator[None, None, None]:
    with open(path, "a+") as f:
        with _locked(f.fileno(), blocked_cb):
            yield


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

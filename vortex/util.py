from __future__ import annotations

import contextlib
import errno
import logging
import os
import shutil
import sys
import webbrowser
from collections.abc import Callable
from collections.abc import Generator
from collections.abc import Iterable
from pathlib import Path
from types import TracebackType
from typing import Any
from typing import IO
from typing import TYPE_CHECKING

import tabulate

if TYPE_CHECKING:
    from vortex.models import DesignObject
    from vortex.models import PuakmaApplication

logger = logging.getLogger("vortex")


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
        if path.exists():
            logger.info(f"Cleaning up {path}...")
            shutil.rmtree(path)
        raise


def print_row_break(center_str: str = "") -> None:
    print("\n", center_str.center(79, "="), "\n")


def shorten_or_pad_text(
    text: str, max_len: int = 30, *, min_len: int = 0, sep: str = "..."
) -> str:
    if len(text) <= max_len:
        if len(text) < min_len:
            text = text.ljust(min_len, ".")
        return text
    max_len -= len(sep)
    start_len = max_len // 2
    end_len = max_len - start_len
    return f"{text[:start_len]}{sep}{text[-end_len:]}"


def render_objects(
    objs: Iterable[DesignObject],
    *,
    show_params: bool = False,
) -> None:
    row_headers = ["ID", "Name", "Type", "Application"]
    row_data = []
    if show_params:
        row_headers.append("Content Type")
        row_headers.append("Open Action")
        row_headers.append("Save Action")
        row_headers.append("Parent Page")
        row_headers.append("Inherit From")
        row_headers.append("Comment")

    for obj in sorted(objs, key=lambda obj: obj.name.casefold()):
        row = [obj.id, obj.name, obj.design_type.name, str(obj.app)]
        if show_params:
            row.append(obj.content_type or "")
            row.append(obj.open_action or "")
            row.append(obj.save_action or "")
            row.append(obj.parent_page or "")
            row.append(obj.inherit_from or "")
            row.append(obj.comment or "")
        row_data.append(row)

    print(tabulate.tabulate(row_data, headers=row_headers))


def render_apps(
    apps: list[PuakmaApplication],
    *,
    show_inherited: bool,
) -> None:
    row_headers = [
        "ID",
        "Name",
        "Group",
        "Template Name",
    ]
    row_data = []

    if show_inherited:
        row_headers.append("Inherits From")

    for app in sorted(apps, key=lambda x: (x.group.casefold(), x.name.casefold())):
        row = [app.id, app.name, app.group, app.template_name]
        if show_inherited:
            row.append(app.inherit_from)
        row_data.append(row)
    print(tabulate.tabulate(row_data, headers=row_headers))


def open_app_urls(
    *apps: PuakmaApplication,
    open_dev_url: bool = True,
) -> None:
    # If we're going to open 10+ urls, lets confirm with the user
    len_apps = len(apps) * (2 if open_dev_url else 1)
    if len_apps > 9 and input(
        f"Open {len_apps} application URLs? Enter '[y]es' to continue: "
    ).strip().lower() not in ["y", "yes"]:
        return
    for app in apps:
        webbrowser.open(app.url)
        if open_dev_url:
            webbrowser.open(app.web_design_url)


def rmtree(path: Path) -> None:
    def _handle_race(
        func: Callable[..., Any],
        path: str,
        exc: tuple[type[OSError], OSError, TracebackType],
    ) -> None:
        # Avoid some race conditions
        excvalue = exc[1]
        if isinstance(excvalue, FileNotFoundError):
            logger.debug(excvalue.strerror)
        elif (
            excvalue.errno == errno.ENOTEMPTY
            and os.path.exists(path)
            and os.path.isdir(path)
        ):
            logger.debug(f"Failed to remove {path}: {excvalue.strerror}. Retrying...")
            shutil.rmtree(path)
            logger.debug(f"Managed to remove {path}.")
        else:
            raise excvalue

    logger.info(f"Cleaning up {path}...")
    shutil.rmtree(path, ignore_errors=False, onerror=_handle_race)

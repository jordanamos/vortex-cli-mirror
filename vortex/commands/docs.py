from __future__ import annotations

import logging
import os
import platform
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger("vortex")


def docs() -> int:
    system = platform.system()
    doc_path = Path(os.path.dirname(__file__), "..", "docs", "Blackbook.pdf").resolve()

    cmd = None
    shell = False

    if system == "Windows":
        cmd = "start"
        shell = True
    # MacOS
    elif system == "Darwin":
        cmd = shutil.which("open")
    elif system == "Linux":
        cmd = shutil.which("xdg-open")

    if cmd is None:
        logger.error("Unable to determine default program to open file.")
        return 1

    try:
        subprocess.Popen(
            [cmd, str(doc_path)],
            shell=shell,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        logger.error(f"Command '{cmd}' not found")
        return 1

    return 0

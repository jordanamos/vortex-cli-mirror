from __future__ import annotations

import logging

from vortex import util
from vortex.workspace import Workspace

logger = logging.getLogger("vortex")


def code(workspace: Workspace, args: list[str]) -> int:
    if not workspace.code_workspace_file.exists() and "--help" not in args:
        logger.error(f"{workspace.code_workspace_file} does not exist")
        return 1

    args.insert(0, str(workspace.code_workspace_file))
    cmd = "code"
    try:
        return util.execute_cmd(cmd, args)
    except FileNotFoundError:
        logger.error(f"VSCode '{cmd}' command not found. Check system PATH.")
        return 1

from __future__ import annotations

import logging
import shutil

from vortex.workspace import Workspace


logger = logging.getLogger("vortex")


def clean(workspace: Workspace) -> int:
    app_dirs = workspace.listdir(strict=False)
    if app_dirs:
        with workspace.exclusive_lock():
            for app_dir in app_dirs:
                shutil.rmtree(app_dir)
                logger.debug(f"Deleted directory '{app_dir}'")
            workspace.update_vscode_settings()
    logger.info("Workspace cleaned")
    return 0

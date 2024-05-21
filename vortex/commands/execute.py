from __future__ import annotations

import logging
from pathlib import Path

from vortex.models import DesignPath
from vortex.models import InvalidDesignPathError
from vortex.models import PuakmaServer
from vortex.workspace import Workspace

logger = logging.getLogger("vortex")

REFRESH_APPLICATION_CMD = "tell agenda run /%s/RefreshDesign?&AppID=%d"
AGENDA_SCHEDULE_CMD = "tell agenda schedule"
RUN_CMD = "tell agenda run /%s"


def execute(
    workspace: Workspace,
    server: PuakmaServer,
    command: str | None,
    refresh_app_id: int | None,
    run_action_path: Path | None,
    show_agenda_schedule: bool,
) -> int:
    if refresh_app_id:
        command = REFRESH_APPLICATION_CMD % (
            server.webdesign_path,
            refresh_app_id,
        )
    elif run_action_path:
        try:
            design_path = DesignPath(
                workspace, run_action_path.resolve(), must_exist=True
            )
        except InvalidDesignPathError as e:
            logger.error(e)
            return 1
        command = RUN_CMD % design_path.server_path
    elif show_agenda_schedule:
        command = AGENDA_SCHEDULE_CMD

    if not command:
        logger.error("No command provided.")
        return 1

    with server as s:
        logger.debug(f"Executing command... {command}")
        resp = s.server_designer.execute_command(command)
    if resp:
        print(resp)
    return 0

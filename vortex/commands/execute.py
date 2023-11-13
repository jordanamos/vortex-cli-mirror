from __future__ import annotations

import logging

from vortex.models import PuakmaServer

logger = logging.getLogger("vortex")

REFRESH_APPLICATION_CMD = "tell agenda run %s/RefreshDesign?&AppID=%d"


def execute(
    server: PuakmaServer,
    command: str | None,
    refresh_app_id: int | None,
) -> int:
    if not command:
        if refresh_app_id:
            command = REFRESH_APPLICATION_CMD % (
                f"/{server.webdesign_path}",
                refresh_app_id,
            )
        else:
            logger.error("No command provided.")
            return 1
    with server as s:
        resp = s.server_designer.execute_command(command)
    if resp:
        print(resp)
    return 0

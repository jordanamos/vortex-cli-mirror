from __future__ import annotations

import logging

from vortex.models import PuakmaServer
from vortex.workspace import SAMPLE_CONFIG
from vortex.workspace import Workspace

logger = logging.getLogger("vortex")


def config(
    workspace: Workspace,
    server: PuakmaServer,
    *,
    print_sample: bool = False,
    update_vscode_settings: bool = False,
    reset_vscode_settings: bool = False,
    output_config_path: bool = False,
    output_workspace_path: bool = False,
    output_server_config: bool = False,
    list_servers: bool = False,
    set: tuple[str, str, str] | None = None,
) -> int:
    if print_sample:
        print(SAMPLE_CONFIG, end="")
    elif update_vscode_settings or reset_vscode_settings:
        workspace.update_vscode_settings(server, reset_vscode_settings)
        status = "reset" if reset_vscode_settings else "updated"
        logger.info(f"VSCode Workspace settings {status}")
    elif output_config_path:
        print(workspace.server_config_file)
    elif output_workspace_path:
        print(workspace.path)
    elif output_server_config:
        workspace.print_server_config_info(server.name)
    elif list_servers:
        for s in workspace.list_servers():
            print(s)
    elif set:
        workspace.set_config(*set)
    return 0

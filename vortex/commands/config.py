from __future__ import annotations

from vortex.workspace import SAMPLE_CONFIG
from vortex.workspace import Workspace


def config(
    workspace: Workspace,
    server_name: str | None,
    *,
    print_sample: bool = False,
    update_vscode_settings: bool = False,
    reset_vscode_settings: bool = False,
    output_config_path: bool = False,
    output_workspace_path: bool = False,
    output_server_config: bool = False,
) -> int:
    if print_sample:
        print(SAMPLE_CONFIG, end="")
    elif update_vscode_settings or reset_vscode_settings:
        workspace.update_vscode_settings(reset_vscode_settings)
        status = "reset" if reset_vscode_settings else "updated"
        print(f"VSCode Workspace settings {status}.")
    elif output_config_path:
        print(workspace.server_config_file)
    elif output_workspace_path:
        print(workspace.path)
    elif output_server_config:
        workspace.print_server_config_info(server_name)
    return 0

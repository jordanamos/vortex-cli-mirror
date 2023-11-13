from __future__ import annotations

from vortex.models import DesignType
from vortex.models import PuakmaServer
from vortex.util import render_objects
from vortex.workspace import Workspace


def find(
    workspace: Workspace,
    server: PuakmaServer,
    name: str,
    *,
    app_ids: list[int] | None = None,
    design_types: list[DesignType] | None = None,
    show_params: bool = False,
    show_ids_only: bool = False,
    strict_search: bool = False,
) -> int:
    if app_ids:
        apps = [workspace.lookup_app(server, id) for id in app_ids]
    else:
        apps = workspace.listapps(server)

    matches = [
        obj
        for app in apps
        for obj in app.design_objects
        if (
            (not strict_search and (name.lower() in obj.name.lower()))
            or (name == obj.name)
        )
        and (not design_types or obj.design_type in design_types)
    ]

    if show_ids_only:
        for obj in matches:
            print(obj.id)
    else:
        render_objects(matches, show_params=show_params)

    return 0

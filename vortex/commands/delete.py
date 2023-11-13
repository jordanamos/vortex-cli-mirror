from __future__ import annotations

import asyncio
import logging

from vortex.colour import Colour
from vortex.models import DesignObject
from vortex.models import PuakmaServer
from vortex.soap import AppDesigner
from vortex.util import render_objects
from vortex.workspace import Workspace

logger = logging.getLogger("vortex")


def delete(
    workspace: Workspace,
    server: PuakmaServer,
    obj_ids: list[int],
) -> int:
    objs = []
    apps = []
    for app in workspace.listapps(server):
        for obj in app.design_objects:
            if obj.id in obj_ids:
                objs.append(obj)
                if app not in apps:
                    apps.append(app)

    if not objs:
        logger.error(f"No cloned Design Object found with ID {obj_ids}")
        return 1

    _deleted = Colour.colour("deleted", Colour.RED)
    print(f"The following Design Objects will be {_deleted}:\n")
    render_objects(objs)
    if input("\n[Y/y] to continue:") not in ["Y", "y"]:
        return 1

    with workspace.exclusive_lock():
        ret = asyncio.run(_adelete_objs(workspace, server, objs))
        for app in apps:
            workspace.mkdir(app)
        return ret


async def _adelete_objs(
    workspace: Workspace, server: PuakmaServer, objs: list[DesignObject]
) -> int:
    async with server as s:
        await s.server_designer.ainitiate_connection()
        tasks = []
        for obj in objs:
            task = asyncio.create_task(_adelete(workspace, s.app_designer, obj))
            tasks.append(task)
        ret = 0
        for done in asyncio.as_completed(tasks):
            try:
                ret |= await done
            except (asyncio.CancelledError, Exception):
                for task in tasks:
                    task.cancel()
                raise
        return ret


async def _adelete(
    workspace: Workspace,
    app_designer: AppDesigner,
    obj: DesignObject,
) -> int:
    await obj.adelete(app_designer)
    obj.app.design_objects.remove(obj)
    path = obj.design_path(workspace).path
    try:
        path.unlink()
        logger.info(f"Deleted Local File: {path}")
    except FileNotFoundError as e:
        err = (
            f"Unable to delete local file because it does not exist: {path}\n"
            "It may have already been deleted or saved without file extension."
        )
        logger.warning(f"{e}: {err}")
    return 0

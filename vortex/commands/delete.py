from __future__ import annotations

import asyncio
import collections
import itertools
import logging
from collections.abc import Iterable

from vortex.colour import Colour
from vortex.models import DesignObject
from vortex.models import DesignObjectAmbiguousError
from vortex.models import DesignObjectNotFound
from vortex.models import PuakmaApplication
from vortex.models import PuakmaServer
from vortex.util import render_objects
from vortex.workspace import Workspace

logger = logging.getLogger("vortex")


async def _adelete_objs(server: PuakmaServer, objs: Iterable[DesignObject]) -> None:
    async with server as s:
        await s.server_designer.ainitiate_connection()
        tasks = []
        for obj in objs:
            task = asyncio.create_task(obj.adelete(s.app_designer))
            tasks.append(task)
        for done in asyncio.as_completed(tasks):
            try:
                await done
            except (asyncio.CancelledError, Exception):
                for task in tasks:
                    task.cancel()
                raise


def delete(
    workspace: Workspace,
    server: PuakmaServer,
    obj_ids: list[int],
) -> int:
    app_objs: dict[PuakmaApplication, list[DesignObject]] = collections.defaultdict(
        list
    )
    for obj_id in obj_ids:
        try:
            _, obj = workspace.lookup_design_obj(server, obj_id)
            app_objs[obj.app].append(obj)
        except (DesignObjectNotFound, DesignObjectAmbiguousError) as e:
            logger.error(e)
            return 1

    all_objs = list(itertools.chain(*app_objs.values()))
    _deleted = Colour.colour("DELETED", Colour.RED)
    print(f"The following Design Objects will be {_deleted}:\n")
    render_objects(all_objs)
    if input("\n[Y/y] to continue:") not in ["Y", "y"]:
        logger.error("Operation Cancelled")
        return 1

    with workspace.exclusive_lock():
        asyncio.run(_adelete_objs(server, all_objs))
        for app, objs in app_objs.items():
            for obj in objs:
                app.design_objects.remove(obj)
                path = obj.design_path(workspace).path
                try:
                    path.unlink()
                    logger.debug(f"Deleted Local File: {path}")
                except FileNotFoundError:
                    msg = (
                        f"Unable to delete local file because it doesn't exist: {path}"
                        "\nIt may have already been deleted or saved without "
                        "a file extension."
                    )
                    logger.warning(msg)
            workspace.mkdir(app)
        return 0

from __future__ import annotations

import asyncio
import logging

from vortex.models import DesignObject
from vortex.models import DesignObjectAmbiguousError
from vortex.models import DesignObjectNotFound
from vortex.models import PuakmaApplication
from vortex.models import PuakmaServer
from vortex.spinner import Spinner
from vortex.util import render_objects
from vortex.workspace import Workspace


logger = logging.getLogger("vortex")


def copy(
    workspace: Workspace,
    server: PuakmaServer,
    obj_ids: list[int],
    to_app_id: int,
    copy_params: bool,
) -> int:
    to_app = workspace.lookup_app(server, to_app_id)
    workspace_apps = workspace.listapps(server)
    workspace_apps.remove(to_app)

    matches = [
        obj for app in workspace_apps for obj in app.design_objects if obj.id in obj_ids
    ]

    if not matches or len(matches) != len(obj_ids):
        logger.error(
            f"Unable to match Design Objects {obj_ids} in {[o.id for o in matches]}"
        )
        return 1

    print(f"The following Objects will be copied to {to_app}:\n")
    render_objects(matches, show_params=copy_params)
    if input("\n[Y/y] to continue:") not in ["Y", "y"]:
        return 1

    with (
        workspace.exclusive_lock(),
        Spinner("Copying..."),
    ):
        return asyncio.run(
            _acopy_objects(workspace, server, to_app, matches, copy_params)
        )


async def _acopy_objects(
    workspace: Workspace,
    server: PuakmaServer,
    to_app: PuakmaApplication,
    objs_to_copy: list[DesignObject],
    copy_params: bool,
) -> int:
    async with server:
        await server.server_designer.ainitiate_connection()
        ret = 0
        tasks = []

        for obj_to_copy in objs_to_copy:
            if to_app.id == obj_to_copy.app.id:
                _err = f"Failed to copy {obj_to_copy} to {to_app}: "
                logger.error(f"{_err} {obj_to_copy} already belongs to {to_app}")
                ret |= 1
                continue

            obj_to_copy.app = to_app

            task = asyncio.create_task(
                _acopy_obj(workspace, server, obj_to_copy, copy_params)
            )
            tasks.append(task)

        for result in asyncio.as_completed(tasks):
            try:
                ret |= await result
            except (Exception, asyncio.CancelledError) as e:
                logger.error(f"Operation Cancelled: {e}")
                for task in tasks:
                    task.cancel()
                ret = 1
                break

        workspace.mkdir(to_app)

    return ret


async def _acopy_obj(
    workspace: Workspace,
    server: PuakmaServer,
    obj: DesignObject,
    copy_params: bool,
) -> int:
    _err_msg = f"Failed to copy {obj} to {obj.app.id}:"

    try:
        indx, existing_obj = obj.app.lookup_design_obj(obj.name)
    except DesignObjectAmbiguousError as e:
        logger.error(f"{_err_msg } {e}")
        return 1
    except DesignObjectNotFound:
        # Create a new object
        obj.id = -1
        ok = await obj.acreate(server.app_designer)
        if not ok:
            logger.error(f"{_err_msg} Unable to create Design Object {obj}")
            return 1
        if copy_params:
            await obj.acreate_params(server.app_designer)

        obj.app.design_objects.append(obj)

    else:
        # Update the existing object
        logger.info(
            f"Design Object {obj} already exists in {obj.app}. "
            "Only the Design data/source will be updated."
        )
        obj.id = existing_obj.id
        obj.app.design_objects[indx].design_data = obj.design_data
        obj.app.design_objects[indx].design_source = obj.design_source

    tasks = []
    if obj.do_save_source:
        upload_src_task = asyncio.create_task(
            obj.aupload(server.download_designer, True)
        )
        tasks.append(upload_src_task)
    upload_data_task = asyncio.create_task(obj.aupload(server.download_designer))
    tasks.append(upload_data_task)

    ret = 0
    for result in asyncio.as_completed(tasks):
        try:
            ok = await result
            ret |= 0 if ok else 1
        except (Exception, asyncio.CancelledError):
            for task in tasks:
                task.cancel()
            raise

    try:
        await asyncio.to_thread(obj.save, workspace)
    except OSError as e:
        logger.error(e.strerror)
        ret = 1

    return ret

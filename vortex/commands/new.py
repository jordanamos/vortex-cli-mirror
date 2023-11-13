from __future__ import annotations

import argparse
import asyncio
import base64
import logging
import mimetypes
from pathlib import Path

from vortex.colour import Colour
from vortex.models import DesignObject
from vortex.models import DesignObjectAmbiguousError
from vortex.models import DesignObjectNotFound
from vortex.models import DesignType
from vortex.models import PuakmaApplication
from vortex.models import PuakmaServer
from vortex.soap import AppDesigner
from vortex.spinner import Spinner
from vortex.util import render_apps
from vortex.util import render_objects
from vortex.workspace import Workspace

logger = logging.getLogger("vortex")


async def _acreate(
    workspace: Workspace,
    app_designer: AppDesigner,
    obj: DesignObject,
) -> int:
    ok = await obj.acreate(app_designer)
    if ok:
        await obj.acreate_params(app_designer)
        obj.app.design_objects.append(obj)
        await asyncio.to_thread(obj.save, workspace)
    return 0 if ok else 1


async def _acreate_objects(
    workspace: Workspace, server: PuakmaServer, objs: list[DesignObject]
) -> int:
    async with server as s:
        await s.server_designer.ainitiate_connection()
        tasks = []
        for obj in objs:
            task = asyncio.create_task(_acreate(workspace, s.app_designer, obj))
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


def _prep_new_object(
    name: str,
    app: PuakmaApplication,
    design_type: DesignType,
    content_type: str | None = None,
    comment: str | None = None,
    inherit_from: str | None = None,
    parent_page: str | None = None,
    open_action: str | None = None,
    save_action: str | None = None,
) -> DesignObject:
    content_type = design_type.content_type() or content_type
    _ext = mimetypes.guess_extension(content_type) if content_type else None
    if _ext is None or content_type is None:
        raise ValueError(f"Unable to determine file type for '{content_type}'")
    design_source = base64.b64encode(design_type.source_template(name)).decode()
    return DesignObject(
        -1,
        name,
        app,
        design_type,
        content_type,
        "",
        design_source,
        comment=comment,
        inherit_from=inherit_from,
        parent_page=parent_page,
        open_action=open_action,
        save_action=save_action,
    )


def _prepare_new_objects(
    name: str,
    app: PuakmaApplication,
    design_type: DesignType,
    content_type: str | None = None,
    comment: str | None = None,
    inherit_from: str | None = None,
    parent_page: str | None = None,
    open_action: str | None = None,
    save_action: str | None = None,
) -> list[DesignObject]:
    objs: list[DesignObject] = []

    if open_action:
        try:
            app.lookup_design_obj(open_action)
        except DesignObjectNotFound:
            objs.append(_prep_new_object(open_action, app, DesignType.ACTION))

    if save_action:
        try:
            app.lookup_design_obj(save_action)
        except DesignObjectNotFound:
            objs.append(_prep_new_object(save_action, app, DesignType.ACTION))

    try:
        _, _new_obj = app.lookup_design_obj(name)
    except DesignObjectNotFound:
        objs.append(
            _prep_new_object(
                name,
                app,
                design_type,
                content_type,
                comment,
                inherit_from,
                parent_page,
                open_action,
                save_action,
            )
        )
    else:
        raise ValueError(f"Design Object {_new_obj} already exists in {app}")
    return objs


def _new_object(
    workspace: Workspace,
    server: PuakmaServer,
    name: str,
    app_id: int,
    design_type: DesignType,
    content_type: str | None = None,
    comment: str | None = None,
    inherit_from: str | None = None,
    parent_page: str | None = None,
    open_action: str | None = None,
    save_action: str | None = None,
) -> int:
    app = workspace.lookup_app(server, app_id)

    try:
        objs = _prepare_new_objects(
            name,
            app,
            design_type,
            content_type,
            comment,
            inherit_from,
            parent_page,
            open_action,
            save_action,
        )
    except (ValueError, DesignObjectAmbiguousError) as e:
        logger.error(e)
        return 1

    _created = Colour.colour("created", Colour.GREEN)
    print(f"The following Design Objects will be {_created} in {app}:\n")
    _show_params = True if parent_page or open_action or save_action else False
    render_objects(objs, show_params=_show_params)
    if input("\n[Y/y] to continue:") not in ["Y", "y"]:
        return 1

    with workspace.exclusive_lock():
        ret = asyncio.run(_acreate_objects(workspace, server, objs))
        workspace.mkdir(app)
        return ret


def _import_pmx(server: PuakmaServer, group: str, name: str, pmx_path: Path) -> int:
    with Spinner("Importing..."):
        with open(pmx_path, "rb") as f:
            pmx_bytes = f.read()

        with server as s:
            app_id = s.download_designer.upload_pmx(group, name, pmx_bytes)
    logger.info(f"Created Application {group}/{name} [{app_id}] from {pmx_path.name}")
    return 0


def _new_app(
    server: PuakmaServer,
    group: str,
    name: str,
    inherit_from: str | None,
    template_name: str | None,
    description: str | None,
    import_path: Path | None,
) -> int:
    if import_path:
        return _import_pmx(server, group, name, import_path)

    app = PuakmaApplication(-1, name, group, inherit_from, template_name, server.host)
    print("The following Application will be created:\n")
    render_apps([app], show_inherited=True)
    if input("\n[Y/y] to continue:") not in ["Y", "y"]:
        return 1

    with server as s:
        app.id = s.app_designer.save_application(
            app.id,
            app.group,
            app.name,
            app.inherit_from,
            app.template_name,
            description,
        )
    logger.info(f"Created Application {app} [{app.id}]")
    return 0


def _new_keyword(
    workspace: Workspace,
    server: PuakmaServer,
    app_id: int,
    name: str,
    values: list[str],
) -> int:
    app = workspace.lookup_app(server, app_id)

    with server as s:
        keyword_id = s.app_designer.save_keyword(app.id, -1, name, values)
    logger.info(f"Created Keyword '{name}' [{keyword_id}]")
    return 0


def new(workspace: Workspace, server: PuakmaServer, args: argparse.Namespace) -> int:
    if args.subcommand == "object":
        return _new_object(
            workspace,
            server,
            app_id=args.app_id,
            name=args.name,
            design_type=args.design_type,
            content_type=args.content_type,
            comment=args.comment,
            inherit_from=args.inherit_from,
            parent_page=args.parent_page,
            open_action=args.open_action,
            save_action=args.save_action,
        )
    elif args.subcommand == "app":
        return _new_app(
            server,
            args.group,
            args.name,
            args.inherit_from,
            args.template,
            args.description,
            args.import_path,
        )
    elif args.subcommand == "keyword":
        return _new_keyword(
            workspace,
            server,
            args.app_id,
            args.name,
            args.values,
        )
    raise NotImplementedError(f"Subcommand '{args.subcommand}' is not implemented.")

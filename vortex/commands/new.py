from __future__ import annotations

import argparse
import asyncio
import base64
import logging
import mimetypes
from pathlib import Path
from typing import Any

import tabulate

from vortex.colour import Colour
from vortex.models import DesignObject
from vortex.models import DesignObjectAmbiguousError
from vortex.models import DesignObjectNotFound
from vortex.models import DesignObjectParam
from vortex.models import DesignType
from vortex.models import PuakmaApplication
from vortex.models import PuakmaServer
from vortex.soap import AppDesigner
from vortex.spinner import Spinner
from vortex.util import render_apps
from vortex.util import render_objects
from vortex.workspace import Workspace

logger = logging.getLogger("vortex")


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
    params = []
    if open_action is not None:
        params.append(DesignObjectParam("OpenAction", open_action))
    if save_action is not None:
        params.append(DesignObjectParam("SaveAction", save_action))
    if parent_page is not None:
        params.append(DesignObjectParam("ParentPage", parent_page))

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
        params=params,
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


def _validate_args_for_type(
    design_type: DesignType,
    **kwargs: Any,
) -> bool:
    _kwarg_keys = {k for k, _v in kwargs.items() if _v is not None}
    valid_args_map = {
        DesignType.PAGE: {"parent_page", "open_action", "save_action", "content_type"},
        DesignType.RESOURCE: {"content_type"},
    }
    valid_args = valid_args_map.get(design_type, set())
    if not _kwarg_keys.issubset(valid_args):
        invalid_keys = _kwarg_keys - valid_args
        logger.error(
            f"Invalid arguments provided for type '{design_type.name}': {invalid_keys}"
        )
        return False
    return True


async def _acreate_or_update_obj(
    workspace: Workspace,
    app_designer: AppDesigner,
    obj: DesignObject,
    recreate_params: bool,
) -> int:
    ok = await obj.acreate_or_update(app_designer)
    if ok:
        if recreate_params and obj.params:
            # No way to know if this way successful for not so
            # assume success always i guess
            await app_designer.aclear_design_object_params(obj.id)
            # Create the params again, hopefully clearing them worked
            # and we dont get duplicates
            await obj.acreate_params(app_designer)
        await asyncio.to_thread(obj.save, workspace)
    return 0 if ok else 1


async def _acreate_or_update_objects(
    workspace: Workspace,
    server: PuakmaServer,
    objs: list[DesignObject],
    recreate_params: bool,
) -> int:
    async with server as s:
        await s.server_designer.ainitiate_connection()
        tasks = []
        for obj in objs:
            task = asyncio.create_task(
                _acreate_or_update_obj(workspace, s.app_designer, obj, recreate_params)
            )
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


def _update_object(
    workspace: Workspace,
    server: PuakmaServer,
    design_obj_id: int,
    **kwargs: Any,
) -> int:
    try:
        _, obj = workspace.lookup_design_obj(server, design_obj_id)
    except (DesignObjectNotFound, DesignObjectAmbiguousError) as e:
        logger.error(e)
        return 1

    _universal_keys = ("name", "design_type", "comment", "inherit_from")
    non_universal_kwargs = dict(kwargs)
    for k in _universal_keys:
        non_universal_kwargs.pop(k)
    if not _validate_args_for_type(obj.design_type, **non_universal_kwargs):
        return 1

    row_headers = ["ID", "Application", "Name"]
    row = [str(obj.id), str(obj.app), obj.name]
    param_name_map = {
        "open_action": "OpenAction",
        "save_action": "SaveAction",
        "parent_page": "ParentPage",
    }
    recreate_params = False

    for key, value in kwargs.items():
        if hasattr(obj, key) and value is not None:
            row_headers.append(Colour.colour(f"new_{key}", Colour.YELLOW))
            row.append(f"{getattr(obj, key)} -> {value}")
            if key in param_name_map:
                param = DesignObjectParam(param_name_map[key], value)
                obj.update_or_append_param(param)
                recreate_params = True
            else:
                setattr(obj, key, value)

    _updated = Colour.colour("UPDATED", Colour.GREEN)
    print(f"The following Design Object(s) will be {_updated}:\n")
    print(tabulate.tabulate([row], headers=row_headers))
    if input("\n[Y/y] to continue:") not in ["Y", "y"]:
        return 1

    with workspace.exclusive_lock():
        ret = asyncio.run(
            _acreate_or_update_objects(workspace, server, [obj], recreate_params)
        )
        workspace.mkdir(obj.app)
        return ret


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
    if not _validate_args_for_type(
        design_type,
        parent_page=parent_page,
        open_action=open_action,
        save_action=save_action,
    ):
        return 1

    _show_params = True if parent_page or open_action or save_action else False
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
    _created = Colour.colour("CREATED", Colour.GREEN)
    print(f"The following Design Object(s) will be {_created}:\n")
    render_objects(objs, show_params=_show_params)
    if input("\n[Y/y] to continue:") not in ["Y", "y"]:
        return 1

    recreate_params = True if parent_page or open_action or save_action else False
    with workspace.exclusive_lock():
        asyncio.run(
            _acreate_or_update_objects(workspace, server, objs, recreate_params)
        )
        app.design_objects.extend(objs)
        workspace.mkdir(app)
        return 0


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
        if args.update_id:
            return _update_object(
                workspace,
                server,
                args.update_id,
                name=args.name,
                design_type=args.design_type,
                content_type=args.content_type,
                comment=args.comment,
                inherit_from=args.inherit_from,
                parent_page=args.parent_page,
                open_action=args.open_action,
                save_action=args.save_action,
            )
        else:
            return _new_object(
                workspace,
                server,
                name=args.name,
                app_id=args.app_id,
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

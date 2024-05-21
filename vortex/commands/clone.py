from __future__ import annotations

import asyncio
import datetime
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from vortex import util
from vortex.models import DatabaseConnection
from vortex.models import DesignObject
from vortex.models import DesignObjectParam
from vortex.models import DesignType
from vortex.models import JavaClassVersion
from vortex.models import PuakmaApplication
from vortex.models import PuakmaServer
from vortex.spinner import Spinner
from vortex.workspace import Workspace

logger = logging.getLogger("vortex")


async def _aexport_pmx(
    server: PuakmaServer,
    app_ids: list[int],
    output_dir: Path,
    timeout: int,  # noqa: ASYNC109
) -> int:
    tasks = []

    async with server as s:
        await s.server_designer.ainitiate_connection()
        for app_id in app_ids:
            task = asyncio.create_task(
                _aexport_app_pmx(server, app_id, output_dir, timeout)
            )
            tasks.append(task)

        ret = 0
        for done in asyncio.as_completed(tasks):
            try:
                ret |= await done
            except (KeyboardInterrupt, Exception):
                for task in tasks:
                    task.cancel()
                raise
            except asyncio.CancelledError:
                logger.error("Operation Cancelled")
                for task in tasks:
                    task.cancel()
                ret = 1
                break
    return ret


async def _aexport_app_pmx(
    server: PuakmaServer,
    app_id: int,
    output_dir: Path,
    timeout: int,  # noqa: ASYNC109
) -> int:
    ret_bytes = await server.download_designer.adownload_pmx(app_id, True, timeout)
    now = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    output_path = output_dir / f"{now}_{server.host}_{app_id}.pmx"
    await asyncio.to_thread(_save_bytes, ret_bytes, output_path)
    logger.info(f"Successfully exported {app_id} to {output_dir}")
    return 0


def _save_objs(
    workspace: Workspace, objs: list[DesignObject], save_resources: bool
) -> None:
    for obj in objs:
        if not obj.is_valid:
            logger.warning(f"Unable to save invalid design object {obj}")
        elif (
            not save_resources
            and obj.design_type == DesignType.RESOURCE
            and not obj.is_jar_library
        ):
            continue
        else:
            obj.save(workspace)


def _aparse_design_objs(
    objs: list[dict[str, Any]], app: PuakmaApplication
) -> list[DesignObject]:
    ret: list[DesignObject] = []
    for obj in objs:
        design_type_id = int(obj["type"])
        name = obj["name"]
        id_ = int(obj["id"])
        ret.append(
            DesignObject(
                id_,
                name,
                app,
                DesignType(design_type_id),
                obj["ctype"],
                obj["data"],
                obj["src"],
            )
        )
    return ret


def _parse_app_xml(
    server: PuakmaServer, app_xml: ET.Element, app_id: int
) -> tuple[PuakmaApplication, ET.Element]:
    app_ele = app_xml.find("puakmaApplication", namespaces=None)
    if not app_ele:
        raise ValueError(f"Application [{app_id}] does not exist")

    db_connections: list[DatabaseConnection] = []
    for db_ele in app_xml.findall(".//database"):
        db_conn = DatabaseConnection(
            int(db_ele.attrib["id"]), db_ele.attrib["name"].lower()
        )
        db_connections.append(db_conn)

    java_version_ele = app_xml.find('.//sysProp[@name="java.class.version"]')
    if java_version_ele is None or java_version_ele.text is None:
        raise ValueError("Java class version not specified")
    major, minor = (int(v) for v in java_version_ele.text.split(".", maxsplit=1))
    version: JavaClassVersion = (major, minor)
    app = PuakmaApplication(
        id=int(app_ele.attrib["id"]),
        name=app_ele.attrib["name"],
        group=app_ele.attrib["group"],
        inherit_from=app_ele.attrib["inherit"],
        template_name=app_ele.attrib["template"],
        java_class_version=version,
        host=server.host,
        db_connections=tuple(db_connections),
    )
    return app, app_ele


def _match_and_validate_design_objs(
    app: PuakmaApplication,
    design_objs: list[DesignObject],
    design_elements: list[ET.Element],
) -> list[DesignObject]:
    new_objects: list[DesignObject] = []
    for ele in design_elements:
        id_ = int(ele.attrib["id"])
        objs = [obj for obj in design_objs if obj.id == id_]

        is_jar_library = ele.attrib.get("library", "false") == "true"
        package = ele.attrib.get("package", None)
        package_dir = Path(*package.split(".")) if package else None

        param_eles = ele.findall(".//designParam")
        params = []
        for param_ele in param_eles:
            param = DesignObjectParam(
                param_ele.attrib["name"], param_ele.attrib["value"]
            )
            params.append(param)
        try:
            obj = objs.pop()
            obj.is_jar_library = is_jar_library or obj.file_ext == ".jar"
            obj.package_dir = package_dir
            obj.params = params
        except IndexError:
            design_type = DesignType(int(ele.attrib["designType"]))
            obj = DesignObject(
                id_,
                ele.attrib["name"],
                app,
                design_type,
                ele.attrib["contentType"],
                "",
                "",
                is_jar_library,
                package_dir,
                "",
                ele.attrib["inherit"],
                params=params,
            )
        new_objects.append(obj)
    return new_objects


def _save_bytes(data: bytes, output_path: Path) -> None:
    with open(output_path, "wb") as f:
        f.write(data)


async def _aclone_app(
    workspace: Workspace,
    server: PuakmaServer,
    app_id: int,
    get_resources: bool,
) -> tuple[PuakmaApplication | None, int]:
    """Clone a Puakma Application into a newly created directory"""

    app_xml, _obj_rows = await asyncio.gather(
        server.app_designer.aget_application_xml(app_id),
        PuakmaApplication.afetch_design_objects(server, app_id, get_resources),
    )

    try:
        app, app_ele = _parse_app_xml(server, app_xml, app_id)
    except (ValueError, KeyError) as e:
        logger.error(e)
        return None, 1

    eles = app_ele.findall("designElement", namespaces=None)
    objs = _aparse_design_objs(_obj_rows, app)
    app.design_objects = _match_and_validate_design_objs(app, objs, eles)
    app_dir = workspace.mkdir(app, True)

    for dir in DesignType.dirs():
        (app_dir / dir).mkdir()

    try:
        logger.debug(f"Saving {len(objs)} Design Objects for [{app}]...")
        await asyncio.to_thread(
            _save_objs, workspace, app.design_objects, get_resources
        )
    except asyncio.CancelledError:
        util.rmtree(app_dir)
        return None, 1

    logger.info(f"Successfully cloned {app}")

    return app, 0


async def _aclone_apps(
    workspace: Workspace,
    server: PuakmaServer,
    app_ids: list[int],
    get_resources: bool,
    open_urls: bool,
) -> int:
    tasks = []
    async with server as s:
        await s.server_designer.ainitiate_connection()
        for app_id in app_ids:
            task = asyncio.create_task(_aclone_app(workspace, s, app_id, get_resources))
            tasks.append(task)

        ret = 0
        for done in asyncio.as_completed(tasks):
            try:
                app, _ret = await done
                if open_urls and app:
                    util.open_app_urls(app)
                ret |= _ret
            except (KeyboardInterrupt, Exception):
                for task in tasks:
                    task.cancel()
                raise
            except asyncio.CancelledError:
                logger.error("Operation Cancelled")
                for task in tasks:
                    task.cancel()
                ret = 1
                break
        else:
            workspace.update_vscode_settings(server=server)
    return ret


def clone(
    workspace: Workspace,
    server: PuakmaServer,
    app_ids: list[int],
    *,
    timeout: int,
    get_resources: bool = False,
    open_urls: bool = False,
    reclone: bool = False,
    export_path: Path | None = None,
) -> int:
    if reclone:
        app_ids.extend(app.id for app in workspace.listapps(server))

    action = "Cloning" if export_path is None else "Exporting"

    with (
        workspace.exclusive_lock(),
        Spinner(f"{action} {len(app_ids)} application(s)..."),
    ):
        if export_path is not None:
            if export_path == Path():
                export_path = workspace.exports_dir
                export_path.mkdir(exist_ok=True)
            elif not export_path.is_dir():
                logger.error(f"'{export_path}' is not a directory.")
                return 1
            ret = asyncio.run(_aexport_pmx(server, app_ids, export_path, timeout))
        else:
            ret = asyncio.run(
                _aclone_apps(workspace, server, app_ids, get_resources, open_urls)
            )
        return ret

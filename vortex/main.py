from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import concurrent.futures
import contextlib
import functools
import logging
import mimetypes
import re
import shutil
import textwrap
import webbrowser
import xml.etree.ElementTree as ET
import zlib
from collections.abc import Generator
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from httpx import HTTPStatusError

from vortex import util
from vortex.models import DesignObject
from vortex.models import DesignType
from vortex.models import JavaClassVersion
from vortex.models import PuakmaApplication
from vortex.models import PuakmaServer
from vortex.watcher import WorkspaceWatcher
from vortex.workspace import SAMPLE_CONFIG
from vortex.workspace import Workspace
from vortex.workspace import WorkspaceError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("httpx").setLevel(logging.ERROR)
logging.getLogger("watchfiles").setLevel(logging.ERROR)

logger = logging.getLogger("vortex")


def watch(workspace: Workspace, server: PuakmaServer) -> int:
    if not workspace.listdir():
        logger.error(f"No application directories to watch in workspace '{workspace}'")
        return 1
    with (
        workspace.exclusive_lock(),
        util.Spinner("Watching workspace, ^C to stop") as spinner,
    ):
        watcher = WorkspaceWatcher(workspace, server, spinner)
        return asyncio.run(watcher.watch())


def fetch_and_parse_app_xml(
    server: PuakmaServer, app_id: int
) -> tuple[PuakmaApplication, ET.Element]:
    app_xml = server.app_designer.get_application_xml(app_id)
    app_ele = app_xml.find("puakmaApplication", namespaces=None)
    if not app_ele:
        raise ValueError(f"Application [{app_id}] does not exist")

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
    )
    return app, app_ele


def match_and_validate_design_objs(
    design_objs: list[DesignObject],
    design_elements: list[ET.Element],
) -> None:
    def validate_crc32_checksum(obj: DesignObject, ele: dict[str, str]) -> bool:
        data = obj.design_source if obj.do_save_source else obj.design_data
        crc32_xml_key = "sourceCrc32" if obj.do_save_source else "dataCrc32"
        crc32_checksum = int(ele.get(crc32_xml_key, 0))
        try:
            return crc32_checksum == zlib.crc32(data)
        except (TypeError, binascii.Error):
            return False

    design_objs_eles = {int(ele.attrib["id"]): ele for ele in design_elements}
    for obj in reversed(design_objs):
        ele = design_objs_eles.get(obj.id)
        if ele is not None:
            obj.is_jar_library = ele.attrib.get("library", "false") == "true"

            package = ele.attrib.get("package", None)
            obj.package_dir = Path(*package.split(".")) if package else None

            open_action_param_ele = ele.find('.//designParam[@name="OpenAction"]')
            if open_action_param_ele is not None:
                obj.open_action = open_action_param_ele.attrib["value"]

            save_action_param_ele = ele.find('.//designParam[@name="SaveAction"]')
            if save_action_param_ele is not None:
                obj.save_action = save_action_param_ele.attrib["value"]
        if ele is None or not validate_crc32_checksum(obj, ele.attrib):
            design_objs.remove(obj)
            logger.warning(
                f"Unable to validate Design Object {obj}. It will not be saved."
            )


def clone(
    workspace: Workspace,
    server: PuakmaServer,
    app_id: int,
    *,
    get_resources: bool,
) -> tuple[PuakmaApplication | None, int]:
    """Clone a Puakma Application into a newly created directory"""

    logger.info(f"Cloning [{app_id}] from {server.host}...")

    try:
        app, app_ele = fetch_and_parse_app_xml(server, app_id)
    except (ValueError, KeyError) as e:
        logger.error(e)
        return None, 1

    logger.info(f"Fetching Design Objects [{app_id}]...")
    objs = app.fetch_design_objects(server, get_resources)
    eles = app_ele.findall("designElement", namespaces=None)

    match_and_validate_design_objs(objs, eles)
    app.design_objects = objs
    app_dir = workspace.mkdir(app, True)

    # TODO: This doesn't catch KeyboardInterupt
    with util.clean_dir_on_failure(app_dir):
        logger.info(f"Saving {len(objs)} ({len(eles)}) Design Objects [{app_id}]...")
        for obj in app.design_objects:
            obj.save(workspace)

    logger.info(f"Successfully cloned {app} into '{app_dir.name}'")

    return app, 0


def open_app_urls(*apps: PuakmaApplication, open_dev_url: bool = True) -> None:
    # If we're going to open 10+ urls, lets confirm with the user
    len_apps = len(apps) * (2 if open_dev_url else 1)
    if len_apps > 9 and input(
        f"Open {len_apps} application URLs? Enter '[y]es' to continue: "
    ).strip().lower() not in ["y", "yes"]:
        return

    for app in apps:
        webbrowser.open(app.url)
        if open_dev_url:
            webbrowser.open(app.web_design_url)


def clone_apps(
    workspace: Workspace,
    server: PuakmaServer,
    app_ids: list[int],
    *,
    get_resources: bool = False,
    open_urls: bool = False,
    reclone: bool = False,
) -> int:
    if reclone:
        app_ids.extend(app.id for app in workspace.listapps())

    with workspace.exclusive_lock(), util.Spinner(f"Cloning {app_ids}..."):
        fn = functools.partial(clone, workspace, server, get_resources=get_resources)
        todo = [id for id in set(app_ids)]
        with (
            server,
            concurrent.futures.ThreadPoolExecutor() as ex,
        ):
            results = ex.map(fn, todo)

        ret = 0
        for app, ret_code in results:
            if open_urls and app:
                open_app_urls(app)
            ret |= ret_code

        ret |= workspace.update_vscode_settings()
    return ret


def _render_app_list(
    apps: list[PuakmaApplication], show_inherited: bool, *, show_headers: bool
) -> None:
    row = "{:<5} {:<25} {:<25} {:<25}"
    row_headers = [
        "ID",
        "Name",
        "Group",
        "Template Name",
    ]

    if show_inherited:
        row = "{:<5} {:<25} {:<25} {:<25} {:<25}"
        row_headers.append("Inherits From")

    if show_headers:
        print(row.format(*row_headers))

    for app in sorted(apps, key=lambda x: (x.group.casefold(), x.name.casefold())):
        row_data = [app.id, app.name, app.group, app.template_name]
        if show_inherited:
            row_data.append(app.inherit_from)
        print(row.format(*row_data))


def list_apps(
    workspace: Workspace,
    server: PuakmaServer,
    *,
    group_filter: list[str],
    name_filter: list[str],
    template_filter: list[str],
    show_ids_only: bool = False,
    show_inherited: bool = False,
    show_local_only: bool = False,
    open_urls: bool = False,
    open_dev_urls: bool = False,
    show_headers: bool = True,
) -> int:
    if show_local_only:
        apps = workspace.listapps()
    else:
        with server as s:
            apps = s.fetch_all_apps(
                name_filter,
                group_filter,
                template_filter,
                show_inherited,
            )
    if open_urls or open_dev_urls:
        open_app_urls(*apps, open_dev_url=open_dev_urls)
    else:
        if show_ids_only:
            for app in apps:
                print(app.id)
        else:
            _render_app_list(apps, show_inherited, show_headers=show_headers)
    return 0


def clean(workspace: Workspace) -> int:
    app_dirs = workspace.listdir(strict=False)
    ret = 0
    if app_dirs:
        with workspace.exclusive_lock():
            for app_dir in app_dirs:
                shutil.rmtree(app_dir)
                logger.info(f"Deleted directory '{app_dir}'")
            ret = workspace.update_vscode_settings()
    return ret


def code(workspace: Workspace, args: list[str]) -> int:
    if not workspace.code_workspace_file.exists() and "--help" not in args:
        raise FileNotFoundError(f"{workspace.code_workspace_file} does not exist")

    args.insert(0, str(workspace.code_workspace_file))
    cmd = "code"
    try:
        return util.execute_cmd(cmd, args)
    except FileNotFoundError:
        logger.error(f"VSCode '{cmd}' command not found. Check system PATH.")
        return 1


def config(
    workspace: Workspace,
    server_name: str | None,
    *,
    init: bool = False,
    print_sample: bool = False,
    update_vscode_settings: bool = False,
    reset_vscode_settings: bool = False,
    output_config_path: bool = False,
    output_workspace_path: bool = False,
) -> int:
    if print_sample:
        print(SAMPLE_CONFIG, end="")
        return 0
    if update_vscode_settings or reset_vscode_settings:
        return workspace.update_vscode_settings(reset_vscode_settings)
    if output_config_path:
        print(workspace.config_file)
        return 0
    if output_workspace_path:
        print(workspace.path)
        return 0
    if not init:
        workspace.print_info()
        util.print_row_break(" Server Info ")
        workspace.print_server_config_info(server_name)
    return 0


def log(server: PuakmaServer, limit: int, *, show_headers: bool = True) -> int:
    with server as s:
        logs = s.get_last_log_items(limit)

    row = "{:<9}{:^5}{:<31}{:<80}"
    row_headers = ("Time", "Type", "Source", "Message")
    if show_headers:
        print(row.format(*row_headers))

    for log in sorted(logs, key=lambda x: (x.id)):
        row_data = [
            datetime.strftime(log.date, "%H:%M:%S"),
            log.type,
            util.shorten_text(log.item_source),
        ]

        log_lines = log.msg.strip().splitlines()
        for i, line in enumerate(log_lines):
            wrapped_lines = textwrap.wrap(line.strip(), width=80)
            for j, output_line in enumerate(wrapped_lines):
                if i == 0 and j == 0:
                    row_data.append(output_line)
                    print(row.format(*row_data))
                    continue
                print(row.format("", "", "", output_line))
    return 0


def _render_objects(
    objs: list[DesignObject], *, show_headers: bool = True, show_actions: bool = False
) -> None:
    row = "{:<6}{:<30}{:^16}{:^25}"
    row_headers = ["ID", "Name", "Type", "Application"]

    if show_actions:
        row = "{:<6}{:<30}{:^16}{:^25}{:<30} {:<30}"
        row_headers.append("Open Action")
        row_headers.append("Save Action")

    if show_headers:
        print(row.format(*row_headers))

    for obj in sorted(objs):
        row_data = [obj.id, obj.name, obj.design_type.name, obj.app.name]
        if show_actions:
            oa = obj.open_action or ""
            sa = obj.save_action or ""
            row_data.append(oa)
            row_data.append(sa)
        print(row.format(*row_data))


def find(
    workspace: Workspace,
    name: str,
    *,
    app_ids: list[int] | None = None,
    design_types: list[DesignType] | None = None,
    show_headers: bool = True,
    exclude_resources: bool = True,
    show_actions: bool = False,
    show_ids_only: bool = False,
) -> int:
    apps = (app for app in workspace.listapps() if (not app_ids or app.id in app_ids))
    if exclude_resources:
        design_types = [t for t in DesignType if t != DesignType.RESOURCE]
    matches = [
        obj
        for app in apps
        for obj in app.design_objects
        if name.lower() in obj.name.lower()
        and (not design_types or obj.design_type in design_types)
    ]

    if show_ids_only:
        for obj in matches:
            print(obj.id)
    else:
        _render_objects(matches, show_headers=show_headers, show_actions=show_actions)

    return 0


def grep(
    workspace: Workspace,
    pattern: str,
    *,
    app_ids: list[int] | None = None,
    design_types: list[DesignType] | None = None,
    output_paths: bool = False,
    exclude_resources: bool = True,
) -> int:
    def _output_match(match: re.Match[bytes]) -> None:
        try:
            text = match.string.decode()
        except UnicodeDecodeError:
            # Found a binary resource or jar library etc., skip
            return
        line_indx = text.count("\n", 0, match.start())
        line_no = line_indx + 1
        if output_paths:
            print(f"{obj.design_path(workspace)}:{line_no}")
        else:
            matched_text = match.group().decode()
            line = text.splitlines()[line_indx].strip()
            new_text = util.Colour.highlight(matched_text, util.Colour.RED, line)
            print(
                f"{util.Colour.highlight(obj.name, util.Colour.BOLD)}"
                f":{line_no}:{new_text}"
            )

    if exclude_resources:
        design_types = [t for t in DesignType if t != DesignType.RESOURCE]

    regex = re.compile(pattern.encode())
    apps = (app for app in workspace.listapps() if (not app_ids or app.id in app_ids))
    objs = [
        obj
        for app in apps
        for obj in app.design_objects
        if (not obj.is_jar_library)
        and (not design_types or obj.design_type in design_types)
    ]
    for obj in sorted(objs):
        bytes_to_search = obj.design_source if obj.do_save_source else obj.design_data
        match = re.search(regex, bytes_to_search)
        _output_match(match) if match else None
    return 0


def _create_obj(workspace: Workspace, server: PuakmaServer, obj: DesignObject) -> int:
    ok = server.app_designer.update_design_object(obj) > 0
    logger.info(f"Created Design Object {obj}: {('OK' if ok else 'ERROR')}")
    if ok:
        obj.save(workspace)
        obj.app.design_objects.append(obj)
        workspace.mkdir(obj.app)
        logger.info(f"Successfully saved {obj}")
    return 0 if ok else 1


def new(
    workspace: Workspace,
    server: PuakmaServer,
    names: list[str],
    app_id: int,
    design_type: DesignType,
    content_type: str | None = None,
    comment: str = "",
    inherit_from: str = "",
) -> int:
    apps = [app for app in workspace.listapps() if app.id == app_id]
    if not apps:
        logger.error(f"No cloned application found with ID {app_id}")
        return 1

    if design_type.is_java_type:
        content_type = "application/java"
    elif design_type == DesignType.PAGE:
        content_type = "text/html"
    _ext = mimetypes.guess_extension(content_type) if content_type else None
    if _ext is None or content_type is None:
        logger.error(f"Unable to determine file type for '{content_type}'")
        return 1

    app = apps.pop()
    objs: list[DesignObject] = []
    for name in names:
        existing_objs = app.lookup_design_obj(name)
        if existing_objs:
            logger.error(
                f"Design Object {[*existing_objs.values()][0]} already exists in {app}"
            )
            continue
        design_source = base64.b64encode(
            (design_type.source_template(name)).encode()
        ).decode()
        objs.append(
            DesignObject(
                -1,
                name,
                design_type,
                content_type,
                "",
                design_source,
                app,
                comment=comment,
                inherit_from=inherit_from,
            )
        )
    if not objs:
        return 1

    print("The following Design Objects will be created:\n")
    _render_objects(objs)
    if input("\n[Y/y] to continue:") not in ["Y", "y"]:
        return 1

    fn = functools.partial(_create_obj, workspace, server)
    with workspace.exclusive_lock(), (
        server
    ), concurrent.futures.ThreadPoolExecutor() as ex:
        results = ex.map(fn, objs)

    ret = 0
    for result in results:
        ret |= result
    return ret


def _delete_obj(workspace: Workspace, server: PuakmaServer, obj: DesignObject) -> int:
    server.app_designer.remove_design_object(obj.id)
    obj.app.design_objects.remove(obj)
    logger.info(f"Deleted Design Object: {obj}")
    path = obj.design_path(workspace).path
    if path.exists():
        path.unlink()
        logger.info(f"Deleted Local File: {path}")
    else:
        err = (
            f"Unable to delete local file because it does not exist: {path}\n"
            "Hint: It may have already been deleted or saved without file extension."
        )
        logger.warning(err)
    workspace.mkdir(obj.app)
    return 0


def delete(
    workspace: Workspace,
    server: PuakmaServer,
    obj_ids: list[int],
) -> int:
    objs = []
    for app in workspace.listapps():
        objs.extend([obj for obj in app.design_objects if obj.id in obj_ids])

    if not objs:
        logger.error(f"No cloned Design Object found with ID {obj_ids}")
        return 1

    _deleted = util.Colour.highlight("deleted", util.Colour.RED)
    print(f"The following Design Objects will be {_deleted}:\n")
    _render_objects(objs)
    if input("\n[Y/y] to continue:") not in ["Y", "y"]:
        return 1

    fn = functools.partial(_delete_obj, workspace, server)
    with (
        workspace.exclusive_lock(),
        server,
        concurrent.futures.ThreadPoolExecutor() as ex,
    ):
        results = ex.map(fn, objs)
    ret = 0
    for result in results:
        ret |= result
    return ret


@contextlib.contextmanager
def error_handler() -> Generator[None, None, None]:
    try:
        yield
    except (WorkspaceError, HTTPStatusError) as e:
        logger.error(e)
        raise SystemExit(1)
    except KeyboardInterrupt:
        raise SystemExit(130)
    except BaseException as e:
        logger.critical(e, stack_info=True, exc_info=True)
        raise SystemExit(1)


def _add_server_option(*parsers: argparse.ArgumentParser) -> None:
    for p in parsers:
        p.add_argument(
            "--server",
            "-s",
            metavar="NAME",
            help="Enter the name of the server definition in the config file to use",
        )


def _add_no_headers_option(*parsers: argparse.ArgumentParser) -> None:
    for p in parsers:
        p.add_argument(
            "--no-headers",
            help="Set this flag to hide the output table headers",
            action="store_false",
            dest="show_headers",
        )


def _add_design_type_option(
    *parsers: argparse.ArgumentParser | argparse._MutuallyExclusiveGroup,
) -> None:
    for p in parsers:
        p.add_argument(
            "--type",
            "-t",
            nargs="*",
            dest="design_type",
            type=DesignType.from_name,
            metavar="DESIGN_TYPE",
            help=(f"Choices: {[t.name.lower() for t in DesignType]}"),
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Vortex command line tool")
    parser.add_argument(
        "--version", "-V", action="version", version=f"vortex-cli {util.VERSION}"
    )
    parser.add_argument(
        "--workspace",
        "-w",
        metavar="DIR",
        help="Override the Workspace directory path",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        help="Set this flag to see DEBUG messages",
        action="store_true",
    )

    command_parser = parser.add_subparsers(dest="command")

    list_parser = command_parser.add_parser(
        "list",
        aliases=("ls",),
        help=(
            "List Puakma Applications on the server or cloned locally."
            "(ls is an alias for 'vortex list --local')"
        ),
    )
    list_parser.add_argument(
        "--group",
        "-g",
        nargs="*",
        help="Enter application 'group' substrings to filter the results",
    )
    list_parser.add_argument(
        "--name",
        "-n",
        nargs="*",
        help="Enter application 'name' substrings to filter the results",
    )
    list_parser.add_argument(
        "--template",
        "-t",
        nargs="*",
        help="Enter application 'template' substrings to filter the results",
    )
    list_parser.add_argument(
        "--local",
        action="store_true",
        dest="show_local_only",
        help="Set this flag to list locally cloned applications instead",
    )
    list_parser.add_argument(
        "--show-inherited",
        help="Set this flag to also display inherited applications",
        action="store_true",
    )
    list_parser.add_argument(
        "--ids-only",
        "-x",
        help=(
            "Set this flag to only display the ID's of the applications in the output"
        ),
        dest="show_ids_only",
        action="store_true",
    )
    list_parser.add_argument(
        "--open-urls",
        "-o",
        help="Set this flag to open each application URL in a web browser",
        action="store_true",
    )
    list_parser.add_argument(
        "--open-dev-urls",
        "-d",
        help="Set this flag to open each application webdesign URL in a web browser",
        action="store_true",
    )

    clone_parser = command_parser.add_parser(
        "clone",
        help="Clone Puakma Applications and their design objects into the workspace",
    )
    clone_parser.add_argument(
        "app_ids",
        nargs="*",
        metavar="APP_ID",
        help="The ID(s) of the Puakma Application(s) to clone",
        type=int,
    )
    clone_parser.add_argument(
        "--get-resources",
        "-r",
        help="Set this flag to also clone the application's resources",
        action="store_true",
    )
    clone_parser.add_argument(
        "--open-urls",
        "-o",
        help="Set this flag to open the application and webdesign URLs after cloning",
        action="store_true",
    )
    clone_parser.add_argument(
        "--reclone",
        help="Set this flag to reclone the already locally cloned applictions",
        action="store_true",
    )
    code_parser = command_parser.add_parser(
        "code",
        help="Open the workspace in Visual Studio Code",
        add_help=False,
    )
    code_parser.add_argument("--help", "-h", action="store_true")

    watch_parser = command_parser.add_parser(
        "watch",
        help=(
            "Watch the workspace for changes to Design Objects "
            "and upload them to the server"
        ),
    )

    command_parser.add_parser(
        "clean",
        help="Delete the cloned Puakma Application directories in the workspace",
    )

    config_parser = command_parser.add_parser(
        "config", help="View and manage configuration"
    )
    # TODO These could probably be a mutexgroup
    config_parser.add_argument(
        "--sample",
        dest="print_sample",
        action="store_true",
        help="Print a sample 'vortex-server-config.ini' file to the console",
    )
    config_parser.add_argument(
        "--update-vscode-settings",
        action="store_true",
        help="Updates the vortex.code-workspace file. Creating it if doesn't exist",
    )
    config_parser.add_argument(
        "--reset-vscode-settings",
        action="store_true",
        help="Recreates the vortex.code-workspace file",
    )
    config_parser.add_argument(
        "--output-config-path",
        action="store_true",
        help="Outputs the file path to the config file",
    )
    config_parser.add_argument(
        "--output-workspace-path",
        action="store_true",
        help="Outputs the file path to the workspace",
    )
    config_parser.add_argument(
        "--init",
        action="store_true",
        help=(
            "Creates the workspace directory and a sample "
            f"'{Workspace.CONFIG_FILE_NAME}' file, if they don't already exist"
        ),
    )

    log_parser = command_parser.add_parser(
        "log",
        help="View the last items in the server log",
    )
    log_parser.add_argument(
        "-n",
        type=int,
        help="The number of logs to return (1 - 50). Default is %(default)s.",
        default=10,
        dest="limit",
    )

    find_parser = command_parser.add_parser(
        "find",
        help="Find Design Objects of cloned applications by name",
        usage="%(prog)s [options] name",
    )
    find_parser.add_argument("name", help="The name of Design Objects to find")
    find_parser.add_argument("--app-id", type=int, nargs="*", dest="app_ids")
    find_parser.add_argument(
        "--ids-only",
        "-x",
        help="Set this flag to only display the ID's of the objects in the output",
        dest="show_ids_only",
        action="store_true",
    )
    find_parser.add_argument(
        "--show-actions",
        help="Set this flag to also display the Open and Save Actions of each object",
        action="store_true",
    )
    find_design_type_mutex = find_parser.add_mutually_exclusive_group()
    find_design_type_mutex.add_argument("--exclude-resources", action="store_true")

    grep_parser = command_parser.add_parser(
        "grep",
        help=(
            "Search the contents of cloned Design Objects using a Regular Expression."
        ),
        usage="%(prog)s [options] pattern",
    )
    grep_parser.add_argument("pattern", help="The Regular Expression pattern to match")
    grep_parser.add_argument("--app-id", type=int, nargs="*", dest="app_ids")
    grep_parser.add_argument("--output-paths", action="store_true")
    grep_design_type_mutex = grep_parser.add_mutually_exclusive_group()
    grep_design_type_mutex.add_argument("--exclude-resources", action="store_true")

    new_parser = command_parser.add_parser("new", help="Create new Design Object(s)")
    new_parser.add_argument("names", nargs="+")
    new_parser.add_argument("--app-id", type=int, required=True)
    new_parser.add_argument("--comment", "-c")
    new_parser.add_argument("--inherit-from")
    new_parser.add_argument(
        "--type",
        "-t",
        dest="design_type",
        type=DesignType.from_name,
        metavar=f"[{', '.join([t.name.lower() for t in DesignType])}]",
        required=True,
    )
    new_parser.add_argument(
        "--content-type", help="The MIME Type. Only used when creating a 'resource'."
    )

    delete_parser = command_parser.add_parser(
        "delete", help="Delete Design Object(s) by ID"
    )
    delete_parser.add_argument(
        "obj_ids", nargs="+", type=int, metavar="DESIGN_OBJECT_ID"
    )

    SERVER_COMMANDS = ("list", "ls", "clone", "watch", "log", "new", "delete")
    _server_parsers = (
        list_parser,
        clone_parser,
        watch_parser,
        log_parser,
        new_parser,
        delete_parser,
    )
    _add_server_option(*_server_parsers, config_parser)
    _add_no_headers_option(list_parser, log_parser, find_parser)
    _add_design_type_option(find_design_type_mutex, grep_design_type_mutex)

    # Validate Arguments
    args, remaining_args = parser.parse_known_args(argv)
    if args.command != "code":
        parser.parse_args(argv)  # Call this for validation
    if args.command == "new" and (
        args.design_type == DesignType.RESOURCE and not args.content_type
    ):
        new_parser.error("--type argument value 'resource' requires --content-type")
    if args.command == "clone" and not (args.app_ids or args.reclone):
        clone_parser.error("Please specifiy the APP_ID[s] to clone or use --reclone")

    # Configure loggers
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logging.getLogger("httpx").setLevel(logging.DEBUG)
        logging.getLogger("watchfiles").setLevel(logging.INFO)

    with error_handler():
        workspace_path = getattr(args, "workspace", None)
        server_name = getattr(args, "server", None)
        init = args.command == "config" and args.init
        workspace = Workspace(workspace_path, init)

        if args.command in SERVER_COMMANDS:
            server = workspace.read_server_from_config(server_name)

            if args.command in ("list", "ls"):
                local_only = args.show_local_only or args.command == "ls"
                return list_apps(
                    workspace,
                    server,
                    group_filter=args.group,
                    name_filter=args.name,
                    template_filter=args.template,
                    show_ids_only=args.show_ids_only,
                    show_inherited=args.show_inherited,
                    show_local_only=local_only,
                    open_urls=args.open_urls,
                    open_dev_urls=args.open_dev_urls,
                    show_headers=args.show_headers,
                )
            elif args.command == "clone":
                return clone_apps(
                    workspace,
                    server,
                    args.app_ids,
                    get_resources=args.get_resources,
                    open_urls=args.open_urls,
                    reclone=args.reclone,
                )
            elif args.command == "watch":
                return watch(workspace, server)
            elif args.command == "log":
                return log(server, args.limit, show_headers=args.show_headers)
            elif args.command == "new":
                return new(
                    workspace,
                    server,
                    app_id=args.app_id,
                    names=args.names,
                    design_type=args.design_type,
                    content_type=args.content_type,
                    comment=args.comment,
                    inherit_from=args.inherit_from,
                )
            elif args.command == "delete":
                return delete(workspace, server, args.obj_ids)
        elif args.command == "clean":
            return clean(workspace)
        elif args.command == "code":
            if args.help:
                code_parser.print_help()
                util.print_row_break()
                remaining_args.insert(0, "--help")
            return code(workspace, remaining_args)
        elif args.command == "config":
            return config(
                workspace,
                server_name,
                init=args.init,
                print_sample=args.print_sample,
                update_vscode_settings=args.update_vscode_settings,
                reset_vscode_settings=args.reset_vscode_settings,
                output_config_path=args.output_config_path,
                output_workspace_path=args.output_workspace_path,
            )
        elif args.command == "find":
            return find(
                workspace,
                args.name,
                app_ids=args.app_ids,
                design_types=args.design_type,
                exclude_resources=args.exclude_resources,
                show_actions=args.show_actions,
                show_ids_only=args.show_ids_only,
            )
        elif args.command == "grep":
            return grep(
                workspace,
                args.pattern,
                app_ids=args.app_ids,
                design_types=args.design_type,
                output_paths=args.output_paths,
                exclude_resources=args.exclude_resources,
            )
        elif args.command:
            raise NotImplementedError(f"Command '{args.command}' is not implemented.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

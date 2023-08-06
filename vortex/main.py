from __future__ import annotations

import argparse
import asyncio
import binascii
import concurrent.futures
import contextlib
import functools
import logging
import os
import shutil
import webbrowser
import xml.etree.ElementTree as ET
import zlib
from collections.abc import Generator
from collections.abc import Sequence

from watchfiles import awatch
from watchfiles import BaseFilter
from watchfiles import Change

from vortex import util
from vortex.models import DesignObject
from vortex.models import DesignPath
from vortex.models import InvalidDesignPathError
from vortex.models import JavaClassVersion
from vortex.models import PuakmaApplication
from vortex.models import PuakmaServer
from vortex.soap import AppDesigner
from vortex.soap import DatabaseDesigner
from vortex.soap import DownloadDesigner
from vortex.soap import ServerDesigner
from vortex.workspace import SAMPLE_CONFIG
from vortex.workspace import ServerConfigError
from vortex.workspace import Workspace
from vortex.workspace import WorkspaceInUseError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logging.getLogger("httpx").setLevel(logging.ERROR)
logging.getLogger("watchfiles").setLevel(logging.ERROR)

logger = logging.getLogger("vortex")


def check_class_file_version(
    class_file_bytes: bytes, expected_version: JavaClassVersion
) -> tuple[bool, str]:
    # https://en.wikipedia.org/wiki/Java_class_file#General_layout
    bytes_header = class_file_bytes[:8]
    if bytes_header[:4] != b"\xca\xfe\xba\xbe":
        return (False, "Not a valid Java Class File")
    major_version = int.from_bytes(bytes_header[6:8], byteorder="big")
    minor_version = int.from_bytes(bytes_header[4:6], byteorder="big")
    compiled_version: JavaClassVersion = (major_version, minor_version)
    if compiled_version != expected_version:
        return (
            False,
            f"File has been compiled with Java Class Version"
            f"{compiled_version} but expected {expected_version}",
        )

    return True, ""


async def _upload_design(
    design_path: DesignPath, download_designer: DownloadDesigner
) -> None:
    app = design_path.app
    with open(design_path, "rb") as f:
        file_bytes = f.read()

    # If we are uploading a class file, lets verify if it has been compiled correctly
    if design_path.file_ext == ".class" and app.java_class_version:
        is_valid, msg = check_class_file_version(file_bytes, app.java_class_version)
        if not is_valid:
            _warn_event(design_path, msg)
            return

    objs = app.lookup_design_obj(design_path.design_name)
    if len(objs) != 1:
        _warn_event(design_path, f"Too many or no matches {objs}")
        return

    obj = objs.pop()
    upload_source = design_path.file_ext == ".java"
    if upload_source:
        obj.design_source = file_bytes
    else:
        obj.design_data = file_bytes
    ok = await obj.upload(download_designer, upload_source)
    _log_upload_status(ok, obj, upload_source)


def _log_upload_status(status_ok: bool, obj: DesignObject, do_source: bool) -> None:
    upload_type = "SOURCE" if do_source else "DATA"
    ok, level = ("OK", logging.INFO) if status_ok else ("ERROR", logging.ERROR)
    logger.log(level, f"Upload {upload_type} of Design Object {obj}: {ok}")


def _warn_event(path: str | DesignPath, err_msg: str) -> None:
    fname = os.path.basename(path)
    logger.warning(f"Failed to process '{fname}': {err_msg}")


async def _handle_changes(
    changes: set[tuple[Change, str]],
    workspace: Workspace,
    download_designer: DownloadDesigner,
) -> None:
    for _, path in changes:
        design_path = DesignPath(workspace, path)
        asyncio.create_task(_upload_design(design_path, download_designer))


class WorkspaceFilter(BaseFilter):
    def __init__(self, workspace: Workspace, server: PuakmaServer) -> None:
        super().__init__()
        self.workspace = workspace
        self.server = server

    def __call__(self, change: Change, path: str) -> bool:
        if os.path.isfile(path) and (
            change == Change.modified
            or (change == Change.added and path.endswith(".class"))
        ):
            try:
                design_path = DesignPath(self.workspace, path)
                design_server = design_path.app.server
                if design_server == self.server:
                    return True
                _warn_event(path, f"({design_server}) does not match ({self.server})")
            except InvalidDesignPathError as e:
                _warn_event(path, str(e))
        return False


async def _watch_for_changes(
    workspace: Workspace,
    server: PuakmaServer,
) -> None:
    async with server.aconnect() as client:
        logger.debug(await ServerDesigner(server, client).ainitiate_connection())
        download_designer = DownloadDesigner(server, client)
        changes = None
        while True:
            try:
                async for changes in awatch(
                    *workspace.listdir(),
                    watch_filter=WorkspaceFilter(workspace, server),
                ):
                    asyncio.create_task(
                        _handle_changes(changes, workspace, download_designer)
                    )
            except Exception as e:
                logger.error(e)
                if changes:
                    asyncio.create_task(
                        _handle_changes(changes, workspace, download_designer)
                    )


def watch(workspace: Workspace, server_name: str | None) -> int:
    if not workspace.listdir():
        logger.error(f"No application directories to watch in workspace '{workspace}'")
        return 1

    try:
        server = workspace.read_server_from_config(server_name)
    except ServerConfigError as e:
        logger.error(e)
        return 1

    with (
        workspace.exclusive_lock(),
        util.spinner("Watching workspace for changes... Press ^C to stop"),
    ):
        asyncio.run(_watch_for_changes(workspace, server))
    return 0


def fetch_and_parse_app_xml(
    app_designer: AppDesigner, app_id: int
) -> tuple[PuakmaApplication, ET.Element]:
    _err_msg = f"Error Cloning Application [{app_id}]: %s"

    app_xml = app_designer.get_application_xml(app_id)
    app_ele = app_xml.find("puakmaApplication", namespaces=None)
    if not app_ele:
        raise ValueError(_err_msg % "Application does not exist")

    java_version_ele = app_xml.find('.//sysProp[@name="java.class.version"]')
    if java_version_ele is None or java_version_ele.text is None:
        raise ValueError(_err_msg % "Java class version not specified")

    major, minor = (int(v) for v in java_version_ele.text.split(".", maxsplit=1))
    version: JavaClassVersion = (major, minor)

    app = PuakmaApplication(
        id=int(app_ele.attrib["id"]),
        name=app_ele.attrib["name"],
        group=app_ele.attrib["group"],
        inherit_from=app_ele.attrib["inherit"],
        template_name=app_ele.attrib["template"],
        java_class_version=version,
        server=app_designer.server,
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

    design_objs_eles = {int(ele.attrib["id"]): ele.attrib for ele in design_elements}

    for obj in reversed(design_objs):
        ele = design_objs_eles.get(obj.id)
        if ele:
            obj.is_jar_library = ele.get("library", "false") == "true"
            obj.package = ele.get("package", None)
        if not ele or not validate_crc32_checksum(obj, ele):
            design_objs.remove(obj)
            logger.warning(
                f"Unable to validate Design Object {obj}. It will not be saved."
            )


def clone(
    app_id: int,
    *,
    workspace: Workspace,
    app_designer: AppDesigner,
    database_designer: DatabaseDesigner,
    get_resources: bool,
) -> tuple[PuakmaApplication | None, int]:
    """Clone a Puakma Application into a newly created directory"""

    logger.info(f"Cloning [{app_id}] from {app_designer.server.host}...")

    try:
        app, app_ele = fetch_and_parse_app_xml(app_designer, app_id)
        design_elements = app_ele.findall("designElement", namespaces=None)
    except (ValueError, KeyError) as e:
        logger.error(e)
        return None, 1

    logger.info(f"Fetching Design Objects for [{app_id}]...")
    design_objects = app.fetch_design_objects(database_designer, get_resources)

    logger.info(
        f"Saving {len(design_objects)} ({len(design_elements)}) "
        f"Design Objects for [{app_id}]..."
    )
    match_and_validate_design_objs(design_objects, design_elements)
    app.design_objects = tuple(design_objects)
    app_dir = workspace.mkdir(app)

    with util.clean_dir_on_failure(app_dir):
        for obj in app.design_objects:
            obj.save(workspace)

    logger.info(f"Successfully cloned [{app_id}] into '{app_dir.name}'")

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
    server_name: str | None,
    app_ids: list[int],
    get_resources: bool,
    open_urls: bool,
) -> int:
    try:
        server = workspace.read_server_from_config(server_name)
    except ServerConfigError as e:
        logger.error(e)
        return 1

    with workspace.exclusive_lock(), server.connect() as client:
        fn = functools.partial(
            clone,
            workspace=workspace,
            app_designer=AppDesigner(server, client),
            database_designer=DatabaseDesigner(server, client),
            get_resources=get_resources,
        )
        todo = [id for id in set(app_ids)]

        with concurrent.futures.ThreadPoolExecutor() as ex:
            results = ex.map(fn, todo)

        ret = 0
        for app, ret_code in results:
            if open_urls and app:
                open_app_urls(app)
            ret |= ret_code

        ret |= workspace.update_vscode_settings()

    return ret


def _render_app_list(apps: list[PuakmaApplication], show_inherited: bool) -> None:
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

    print(row.format(*row_headers))

    for app in sorted(apps, key=lambda x: (x.group.casefold(), x.name.casefold())):
        row_data = [app.id, app.name, app.group, app.template_name]
        if show_inherited:
            row_data.append(app.inherit_from)
        print(row.format(*row_data))


def list_(
    workspace: Workspace,
    server_name: str | None,
    group_filter: str,
    name_filter: str,
    template_filter: str,
    show_ids_only: bool,
    show_inherited: bool,
    show_local_only: bool,
    open_urls: bool,
    open_dev_urls: bool,
) -> int:
    """list puakma applications on the server"""

    if show_local_only:
        apps = workspace.apps()
    else:
        try:
            server = workspace.read_server_from_config(server_name)
        except ServerConfigError as e:
            logger.error(e)
            return 1

        with server.connect() as client:
            database_designer = DatabaseDesigner(server, client)
            apps = server.fetch_all_apps(
                database_designer,
                name_filter,
                group_filter,
                template_filter,
                show_inherited,
            )

    if open_urls or open_dev_urls:
        open_app_urls(*apps, open_dev_url=open_dev_urls)
        return 0

    if show_ids_only:
        for app in apps:
            print(app.id)
    else:
        _render_app_list(apps, show_inherited)

    return 0


def clean(workspace: Workspace) -> int:
    app_dirs = workspace.listdir()
    ret = 0
    if app_dirs:
        with workspace.exclusive_lock():
            for app_dir in app_dirs:
                shutil.rmtree(app_dir)
                logger.info(f"Deleted application directory '{app_dir}'")
            ret = workspace.update_vscode_settings()
    return ret


def code(workspace: Workspace, args: list[str]) -> int:
    if not os.path.exists(workspace.code_workspace_file) and "--help" not in args:
        raise FileNotFoundError(f"{workspace.code_workspace_file} does not exist")

    args.insert(0, str(workspace.code_workspace_file))

    try:
        return util.execute_cmd("code", args)
    except FileNotFoundError:
        raise FileNotFoundError(
            "Unable to open Visual Studio Code. "
            "Couldn't find 'code' executable in system PATH."
        )


def config(
    workspace: Workspace,
    server_name: str | None,
    init: bool,
    print_sample: bool,
    update_vscode_settings: bool,
    reset_vscode_settings: bool,
    output_config_path: bool,
    output_workspace_path: bool,
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


@contextlib.contextmanager
def error_handler() -> Generator[None, None, None]:
    try:
        yield
    except WorkspaceInUseError as e:
        logger.error(e)
        raise SystemExit(1)
    except KeyboardInterrupt:
        raise SystemExit(130)
    except BaseException as e:
        logger.error(e, stack_info=True, exc_info=True)
        raise SystemExit(1)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Vortex command line tool")
    parser.add_argument(
        "--version", action="version", version=f"vortex-cli {util.VERSION}"
    )
    parser.add_argument(
        "--workspace",
        "-w",
        metavar="DIR",
        help="Override the Workspace directory path",
    )

    command_parser = parser.add_subparsers(dest="command")

    list_parser = command_parser.add_parser(
        "list",
        aliases=("ls",),
        help="List Puakma Applications on the server or cloned locally",
    )
    list_parser.add_argument(
        "--server",
        "-s",
        help="Enter the name of the server definition in the config file to use",
    )
    list_parser.add_argument(
        "--group",
        "-g",
        help="Enter an application 'group' substring to filter the results",
    )
    list_parser.add_argument(
        "--name",
        "-n",
        help="Enter an application 'name' substring to filter the results",
    )
    list_parser.add_argument(
        "--template",
        "-t",
        help="Enter an application 'template' substring to filter the results",
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
        "--output-ids-only",
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
        help="Clone a Puakma Application and it's design objects into the workspace",
    )
    clone_parser.add_argument(
        "--server",
        "-s",
        help="Enter the name of the server definition in the config file to use",
    )
    clone_parser.add_argument(
        "app_ids",
        nargs="+",
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
    code_parser = command_parser.add_parser(
        "code",
        help="Open the workspace in Visual Studio Code",
        add_help=False,
    )
    code_parser.add_argument("--help", "-h", action="store_true")

    watch_parser = command_parser.add_parser(
        "watch",
        help=(
            "Watch the workspace for changes to design objects "
            "and upload them to the server"
        ),
    )
    watch_parser.add_argument(
        "--server",
        "-s",
        help="Enter the name of the server definition in the config file to use",
    )
    watch_parser.add_argument(
        "--debug", help="Set this flag to see DEBUG messages", action="store_true"
    )

    command_parser.add_parser(
        "clean",
        help="Delete the cloned Puakma Application directories in the workspace",
    )

    config_parser = command_parser.add_parser(
        "config", help="View and manage configuration"
    )
    config_parser.add_argument(
        "--server",
        "-s",
        help="Enter the name of the server definition in the config file to use",
    )
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
            "'vortex-server-config.ini' file, if they don't already exist"
        ),
    )

    args, remaining_args = parser.parse_known_args(argv)

    if args.command != "code":
        # call this for validation
        parser.parse_args(argv)

    with error_handler():
        workspace_path = getattr(args, "workspace", None)
        server_name = getattr(args, "server", None)

        try:
            do_init = args.command == "config" and args.init
            workspace = Workspace(workspace_path, do_init)
        except NotADirectoryError:
            logger.error(
                f"Workspace {workspace_path} does not exist. "
                "Hint: You can create it with 'vortex config --init'."
            )
            return 1

        if args.command in ("list", "ls"):
            return list_(
                workspace,
                server_name,
                args.group,
                args.name,
                args.template,
                args.show_ids_only,
                args.show_inherited,
                args.show_local_only,
                args.open_urls,
                args.open_dev_urls,
            )
        elif args.command == "clone":
            return clone_apps(
                workspace, server_name, args.app_ids, args.get_resources, args.open_urls
            )
        elif args.command == "watch":
            if args.debug:
                logger.setLevel(logging.DEBUG)
            return watch(workspace, server_name)
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
                args.init,
                args.print_sample,
                args.update_vscode_settings,
                args.reset_vscode_settings,
                args.output_config_path,
                args.output_workspace_path,
            )
        elif args.command:
            raise NotImplementedError(f"Command '{args.command}' is not implemented.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

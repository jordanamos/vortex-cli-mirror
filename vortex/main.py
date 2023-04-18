from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import itertools
import json
import logging
import os
import platform
import shutil
import textwrap
import time
import xml.etree.ElementTree as ET
import zlib
from collections.abc import Generator
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from requests import HTTPError
from requests import Session
from watchdog.events import FileSystemEvent
from watchdog.events import PatternMatchingEventHandler

if platform.system() == "Linux" and "microsoft" in platform.release().lower():
    from watchdog.observers.polling import PollingObserver as Observer
else:
    from watchdog.observers import Observer

from vortex import util
from vortex.models import DesignObject
from vortex.models import DesignPath
from vortex.models import DesignType
from vortex.models import PuakmaApplication
from vortex.models import PuakmaServer
from vortex.soap import AppDesigner
from vortex.soap import DatabaseDesigner
from vortex.soap import DownloadDesigner
from vortex.soap import SOAPResponseParseError
from vortex.workspace import Workspace
from vortex.workspace import WorkspaceConfigError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)

logger = logging.getLogger("vortex")


class WorkspaceEventHandler(PatternMatchingEventHandler):
    def __init__(
        self,
        workspace: Workspace,
        download_designer: DownloadDesigner,
        database_designer: DatabaseDesigner,
        patterns: Sequence[str] | None = None,
        ignore_patterns: Sequence[str] | None = None,
        ignore_directories: bool = False,
        case_sensitive: bool = False,
    ) -> None:
        super().__init__(patterns, ignore_patterns, ignore_directories, case_sensitive)
        self.workspace = workspace
        self.download_designer = download_designer
        self.database_designer = database_designer

    def on_modified(self, event: FileSystemEvent) -> None:
        try:
            design_path = DesignPath(self.workspace, event.src_path)
            file_ext = design_path.file_ext
            app = design_path.app
            if app.server != self.workspace.server:
                raise ValueError("Application server and Workspace server do not match")

            def _blocked_cb() -> None:
                logger.info(f"Locking {design_path}...")

            with util.file_lock(design_path.path, _blocked_cb):
                if file_ext == ".class" and app.java_class_version:
                    check_class_file_version(design_path.path, app.java_class_version)
                obj = app.fetch_design_object(
                    self.database_designer, design_path.design_name
                )
                do_source = obj.design_type.is_java_type and file_ext == ".java"
                obj.set_data(design_path, do_source)
            ok = obj.upload(self.download_designer, do_source)
            self._log_upload_status(ok, obj, do_source)
        except ValueError as e:
            fname = os.path.basename(event.src_path)
            logger.warning(f"Failed to upload Design Object '{fname}': {e}")
        except (HTTPError, SOAPResponseParseError) as e:
            logger.error(e)
            raise SystemExit

    def on_created(self, event: FileSystemEvent) -> None:
        ...

    def on_deleted(self, event: FileSystemEvent) -> None:
        ...

    @staticmethod
    def _log_upload_status(status_ok: bool, obj: DesignObject, do_source: bool) -> None:
        upload_type = "SOURCE" if do_source else "DATA"
        ok, level = ("OK", logging.INFO) if status_ok else ("ERROR", logging.ERROR)
        logger.log(level, f"Upload {upload_type} of Design Object '{obj}': {ok}")


@contextlib.contextmanager
def observe(workspace: Workspace, session: Session) -> Generator[Observer, None, None]:
    observer = Observer()
    handler = WorkspaceEventHandler(
        workspace=workspace,
        download_designer=DownloadDesigner(workspace.server, session),
        database_designer=DatabaseDesigner(workspace.server, session),
        ignore_directories=True,
        ignore_patterns=[str(workspace.code_workspace_file)],
    )
    try:
        observer.schedule(handler, workspace.directory, recursive=True)
        observer.start()
        logger.info(f"Watching '{workspace.directory}' for changes... Press ^C to stop")
        yield observer
    except KeyboardInterrupt:
        pass
    finally:
        observer.stop()
        observer.join()
        logger.info(f"Stopped watching '{workspace.directory}'")


def watch(workspace: Workspace) -> int:
    if not workspace.listdir():
        logger.error(f"No application directories to watch in workspace '{workspace}'")
        return 1
    with (
        workspace.exclusive_lock(),
        workspace.server.session() as session,
        observe(workspace, session) as observer,
    ):
        while observer.is_alive():
            time.sleep(1)
    return 0


def check_class_file_version(
    class_file: Path, expected_version: util.JavaClassVersion
) -> None:
    """Validates the class version of a given file otherwise raises ValueError"""
    # https://en.wikipedia.org/wiki/Java_class_file#General_layout
    with open(class_file, "rb") as f:
        bytes_header = f.read(8)
    if bytes_header[:4] != b"\xca\xfe\xba\xbe":
        raise ValueError(f"{class_file} is not a valid java class file")
    major_version = int.from_bytes(bytes_header[6:8], byteorder="big")
    minor_version = int.from_bytes(bytes_header[4:6], byteorder="big")
    compiled_version = util.JavaClassVersion(major_version, minor_version)
    if compiled_version != expected_version:
        raise ValueError(
            f"{class_file} has been compiled with {compiled_version} "
            f"but expected {expected_version}"
        )


def fetch_and_parse_app_xml(
    app_designer: AppDesigner, app_id: int
) -> tuple[PuakmaApplication, ET.Element]:
    app_xml = app_designer.get_application_xml(app_id)
    app_ele = app_xml.find("puakmaApplication", namespaces=None)
    if not app_ele:
        raise ValueError("Application does not exist")
    java_version_ele = app_xml.find('.//sysProp[@name="java.class.version"]')
    if java_version_ele is None or java_version_ele.text is None:
        raise ValueError("Java class version not specified")
    major, minor = (int(v) for v in java_version_ele.text.split(".", maxsplit=1))
    version = util.JavaClassVersion(major, minor)
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


def fetch_and_match_design_objs(
    db_designer: DatabaseDesigner,
    app: PuakmaApplication,
    get_resources: bool,
    app_ele: ET.Element,
) -> tuple[DesignObject, ...]:
    def validate_crc32_checksum(obj: DesignObject, ele: dict[str, str]) -> bool:
        validate_source = obj.design_type.is_java_type
        base64_data = obj.design_source if validate_source else obj.design_data
        crc32_xml_key = "sourceCrc32" if validate_source else "dataCrc32"
        crc32_checksum = int(ele.get(crc32_xml_key, 0))
        try:
            decoded_data = base64.b64decode(base64_data)
            return crc32_checksum == zlib.crc32(decoded_data)
        except (TypeError, binascii.Error):
            return False

    design_objs = app.fetch_all_design_objects(db_designer, get_resources)
    design_objs_eles = {
        int(obj.attrib["id"]): obj.attrib
        for obj in app_ele.findall("designElement", namespaces=None)
    }
    for obj in reversed(design_objs):
        ele = design_objs_eles.get(obj.id)
        if ele and validate_crc32_checksum(obj, ele):
            obj.is_jar_library = ele.get("library", "false") == "true"
            obj.package = ele.get("package", None)
        else:
            logger.error(
                f"Unable to validate Design Object {obj}. The object will not be saved."
            )
            design_objs.remove(obj)
    return tuple(design_objs)


def clone(
    workspace: Workspace,
    app_designer: AppDesigner,
    database_designer: DatabaseDesigner,
    app_id: int,
    get_resources: bool,
) -> int:
    """Clone a Puakma Application into a newly created directory"""
    try:
        app, app_ele = fetch_and_parse_app_xml(app_designer, app_id)
    except ValueError as e:
        raise ValueError(f"Error Cloning Application [{app_id}]: {e}")
    else:
        design_objects = fetch_and_match_design_objs(
            database_designer, app, get_resources, app_ele
        )
        app_dir = workspace.mkdir(app)
        with util.clean_dir_on_failure(app_dir):
            for obj in design_objects:
                obj.save(workspace)
    return 0


def clone_apps(workspace: Workspace, app_ids: list[int], get_resources: bool) -> int:
    try:
        ret = 0
        with workspace.exclusive_lock(), workspace.server.session() as sess:
            app_designer = AppDesigner(workspace.server, sess)
            db_designer = DatabaseDesigner(workspace.server, sess)
            for id in app_ids:
                logger.info(f"Cloning [{id}] into '{workspace.directory}'")
                ret |= clone(workspace, app_designer, db_designer, id, get_resources)
                logger.info("Clone successful")
    except (HTTPError, SOAPResponseParseError, ValueError) as e:
        logger.error(e)
        ret = 1
    except KeyboardInterrupt:
        ret = 1
    else:
        ret |= update_vscode_settings(workspace)
    return ret


def update_vscode_settings(workspace: Workspace, reset: bool = False) -> int:
    """Updates or creates the vortex.code-workspace file inside the .vscode directory"""

    def _reset() -> dict[Any, Any]:
        if not workspace.vscode_directory.exists():
            workspace.vscode_directory.mkdir()
        return {}

    if reset:
        workspace_settings = _reset()
    else:
        try:
            with open(workspace.code_workspace_file) as f:
                workspace_settings = json.load(f)
        except FileNotFoundError:
            workspace_settings = _reset()
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing {workspace.code_workspace_file}: {e}")
            logger.info("Unable to update vscode workspace settings.")
            return 1

    # Folder settings
    workspace_folders = [
        os.path.join("..", dir.name) for dir in (Path(".vscode"), *workspace.listdir())
    ]
    folder_settings = {"folders": [{"path": folder} for folder in workspace_folders]}

    # Java project settings
    puakma_path = os.path.join(os.path.dirname(__file__), "puakma")
    jar_files = "*.jar"
    java_project_settings = {
        "java.project.sourcePaths": DesignType.source_dirs(),
        "java.project.outputPath": "zbin",
        "java.project.referencedLibraries": [
            os.path.join("zlib", "**", jar_files),
            os.path.join(puakma_path, "*", jar_files),
            # intentionally separated so they can be commented out when conflicting
            os.path.join(puakma_path, "lib", "poi_3.10.1", jar_files),
            os.path.join(puakma_path, "lib", "poi_3.17", jar_files),
        ],
    }
    settings = workspace_settings.get("settings", {})
    settings.update(java_project_settings)

    # Extension reccommendation settings
    extension_settings = {"recommendations": ["vscjava.vscode-java-pack"]}
    extensions = workspace_settings.get("extensions", {})
    extensions.update(extension_settings)

    workspace_settings.update(
        folder_settings | {"settings": settings} | {"extensions": extensions}
    )

    with open(workspace.code_workspace_file, "w") as f:
        json.dump(workspace_settings, f, indent=2)
    status = "Reset" if reset else "Updated"
    logger.info(f"{status} settings in '{workspace.code_workspace_file}'")
    return 0


def list_(
    server: PuakmaServer,
    group_filter: str,
    name_filter: str,
    show_inherited: bool = False,
) -> int:
    """list puakma applications on the server"""
    try:
        with server.session() as sess:
            database_designer = DatabaseDesigner(server, sess)
            apps = server.fetch_all_apps(
                database_designer, name_filter, group_filter, show_inherited
            )
    except (SOAPResponseParseError, HTTPError) as e:
        logger.error(e)
        return 1

    row = "{:<5} {:<25} {:<10} {:<10}"
    for key, grouped_apps in itertools.groupby(apps, key=lambda x: x.group):
        util.print_row_break(f" {key} ")
        print("".join([row.format("ID", "Name", "Template", "Inherit")]))
        for app in sorted(grouped_apps, key=lambda x: x.name.casefold()):
            is_template = "Y" if app.template_name else "N"
            print(row.format(str(app.id), app.name, is_template, app.inherit_from))
    return 0


def clean(workspace: Workspace) -> int:
    app_dirs = workspace.listdir()
    if app_dirs:
        with workspace.exclusive_lock():
            for app_dir in app_dirs:
                shutil.rmtree(app_dir)
                logger.info(f"Deleted application directory '{app_dir}'")
            update_vscode_settings(workspace)
    return 0


def code(workspace: Workspace, args: list[str]) -> int:
    if not os.path.exists(workspace.code_workspace_file) and "--help" not in args:
        logger.error(f"{workspace.code_workspace_file} does not exist")
        return 1

    args.insert(0, str(workspace.code_workspace_file))

    try:
        return util.execute_cmd("code", args)
    except FileNotFoundError as e:
        logger.error(f"Error opening Visual Studio Code: {e}")
        return 1


def sample_config() -> int:
    SAMPLE_CONFIG = textwrap.dedent(
        """\
        [dev]
        host =
        port = 80
        soap_path = system/SOAPDesigner.pma
        puakma_db_conn_id =
        username =
        password =
    """
    )
    print(SAMPLE_CONFIG, end="")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Vortex command line tool")
    command_parser = parser.add_subparsers(dest="command")

    list_parser = command_parser.add_parser(
        "list", help="List Puakma Applications on the server"
    )
    list_parser.add_argument(
        "--group", help="Enter an application 'group' substring to filter the results"
    )
    list_parser.add_argument(
        "--name", help="Enter an application 'name' substring to filter the results"
    )
    list_parser.add_argument(
        "-a",
        "--all",
        help="Set this flag to also display inherited applications",
        dest="show_inherited",
        action="store_true",
    )
    clone_parser = command_parser.add_parser(
        "clone",
        help="Clone a Puakma Application and it's design objects into the workspace",
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
        help="Set this flag to also clone the application's resources",
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
    clean_parser = command_parser.add_parser(
        "clean",
        help="Delete the cloned Puakma Application directories in the workspace",
    )
    update_vscode_settings_parser = command_parser.add_parser(
        "update-vscode-settings",
        help=(
            "Updates the vortex.code-workspace file or creates it if doesnt exist."
            " (Called automatically after 'clone' or 'clean')"
        ),
    )
    update_vscode_settings_parser.add_argument(
        "--reset",
        help="Overwrites and resets the vortex.code-workspace file",
        action="store_true",
    )

    command_parser.add_parser(
        "sample-config", help="Print a sample vortex-server-config.ini file"
    )

    def _add_workspace_option(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--workspace",
            metavar="DIR",
            help=(
                "Override the Workspace directory path. "
                f"Default is '{Workspace.get_default_workspace()}'"
            ),
        )

    def _add_server_option(parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--server",
            help="Enter the name of the server definition in the config file to use",
        )

    _add_workspace_option(clone_parser)
    _add_workspace_option(watch_parser)
    _add_workspace_option(code_parser)
    _add_workspace_option(clean_parser)
    _add_workspace_option(update_vscode_settings_parser)

    _add_server_option(list_parser)
    _add_server_option(clone_parser)
    _add_server_option(watch_parser)

    args, remaining_args = parser.parse_known_args(argv)
    if args.command != "code":
        # call this for validation
        parser.parse_args(argv)

    if args.command == "sample-config":
        return sample_config()

    try:
        workspace = Workspace(
            getattr(args, "workspace", None), getattr(args, "server", None)
        )
    except (WorkspaceConfigError, NotADirectoryError) as e:
        logger.error(e)
        return 1

    if args.command == "list":
        return list_(workspace.server, args.group, args.name, args.show_inherited)
    elif args.command == "clone":
        return clone_apps(workspace, args.app_ids, args.get_resources)
    elif args.command == "watch":
        return watch(workspace)
    elif args.command == "clean":
        return clean(workspace)
    elif args.command == "update-vscode-settings":
        return update_vscode_settings(workspace, args.reset)
    elif args.command == "code":
        if args.help:
            code_parser.print_help()
            util.print_row_break()
            remaining_args.insert(0, "--help")
        return code(workspace, remaining_args)
    elif args.command:
        raise NotImplementedError(f"Command '{args.command}' is not implemented.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

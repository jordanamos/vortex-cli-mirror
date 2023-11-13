from __future__ import annotations

import configparser
import contextlib
import json
import logging
import os
import pickle
import shutil
from collections.abc import Generator
from pathlib import Path
from typing import Any
from typing import NoReturn

from vortex.models import DesignType
from vortex.models import PuakmaApplication
from vortex.models import PuakmaServer
from vortex.util import file_lock

logger = logging.getLogger("vortex")

SAMPLE_CONFIG = """\
[dev]
host =
port = 80
soap_path = system/SOAPDesigner.pma
web_design_path = system/webdesign.pma
puakma_db_conn_id =
username =
password =
"""


class WorkspaceError(Exception):
    pass


class WorkspaceInUseError(WorkspaceError):
    pass


class ServerConfigError(WorkspaceError):
    pass


class PuakmaApplicationNotFound(WorkspaceError):
    pass


class Workspace:
    ENV_VAR = "VORTEX_HOME"

    def __init__(self, path: str | None = None, init: bool = False) -> None:
        self._path = Path(path or Workspace.get_default_workspace())
        if init:
            self.init()
        if not self._path.is_dir():
            raise WorkspaceError(
                f"Workspace path '{self._path}' does not exist."
                " You can create it with '--init'."
            )
        if not os.access(self._path, os.W_OK):
            raise WorkspaceError(f"Workspace '{self._path}' is not writeable.")

    def __str__(self) -> str:
        return str(self._path)

    @property
    def path(self) -> Path:
        return self._path

    @property
    def config_dir(self) -> Path:
        return self.path / "config"

    @property
    def server_config_file(self) -> Path:
        return self.config_dir / "servers.ini"

    @property
    def vscode_dir(self) -> Path:
        return self.path / ".vscode"

    @property
    def exports_dir(self) -> Path:
        return self.path / "exports"

    @property
    def logs_dir(self) -> Path:
        return self.path / "logs"

    @property
    def code_workspace_file(self) -> Path:
        return self.vscode_dir / "vortex.code-workspace"

    def lookup_app(self, server: PuakmaServer, app_id: int) -> PuakmaApplication:
        for app in self.listapps(server):
            if app.id == app_id:
                return app
        raise PuakmaApplicationNotFound(f"No local application found with ID {app_id}")

    def print_server_config_info(self, server_section: str | None) -> None:
        config = configparser.ConfigParser()
        config.read(self.server_config_file)
        section = server_section or config.sections()[0] if config.sections() else ""
        try:
            items = config.items(section)
            print(f"[{section}]")
            for k, v in items:
                if k == "password" and v:
                    v = "<set>"
                print(f"{k}: {v}")
        except configparser.NoSectionError:
            logger.error(f"No server definition found for '{server_section}'")

    @classmethod
    def get_default_workspace(cls) -> str:
        path = os.getenv(cls.ENV_VAR)
        if not path:
            path = os.path.join(os.path.expanduser("~"), "vortex-cli-workspace")
            logger.debug(f"'{Workspace.ENV_VAR}' not set. Using default {path}")
        return os.path.realpath(path)

    def init(self) -> None:
        dirs = [self.path, self.config_dir]
        for dir in dirs:
            if not dir.is_dir():
                dir.mkdir()

        if not self.server_config_file.exists():
            with open(self.server_config_file, "w") as f:
                f.write(SAMPLE_CONFIG)

        if not self.code_workspace_file.exists():
            self.update_vscode_settings(reset=True)

        logger.info(f"Initialised workspace {self.path}")

    @contextlib.contextmanager
    def exclusive_lock(self) -> Generator[None, None, None]:
        def _blocked_cb() -> NoReturn:
            raise WorkspaceInUseError(f"The workspace '{self.path}' is already in use.")

        with file_lock(self.path / ".lock", _blocked_cb):
            yield

    def mkdir(self, app: PuakmaApplication, force_recreate: bool = False) -> Path:
        """
        Creates a .PuakmaApplication.pickle file within a newly created app directory
        with the format 'host_group_name' inside the workspace.
        Returns the full path to the new app directory
        """
        app_path = self.path / app.dir_name
        if app_path.exists() and force_recreate:
            shutil.rmtree(app_path)
        app_path.mkdir(exist_ok=True)
        with open(app_path / app.PICKLE_FILE, "wb") as f:
            pickle.dump(app, f)
        return app_path

    def listdir(
        self, server: PuakmaServer | None = None, *, strict: bool = True
    ) -> list[Path]:
        """
        Returns a list of directories that contain a parseable
        .PuakmaApplication.pickle file.

        If strict is False then return directories that simply
        contain a .PuakmaApplication.pickle file.
        """
        ret = []
        for sub_dir in self.path.iterdir():
            if sub_dir.is_dir():
                if strict:
                    try:
                        app = PuakmaApplication.from_dir(sub_dir)
                        if server and app.host != server.host:
                            continue
                    except ValueError:
                        continue
                else:
                    pickle_file = sub_dir / PuakmaApplication.PICKLE_FILE
                    if not pickle_file.exists():
                        continue
                ret.append(sub_dir)
        return ret

    def listapps(self, server: PuakmaServer | None = None) -> list[PuakmaApplication]:
        return [PuakmaApplication.from_dir(dir) for dir in self.listdir(server)]

    def read_server_from_config(self, server_name: str | None = None) -> PuakmaServer:
        def _error(msg: str) -> NoReturn:
            raise ServerConfigError(
                f"{msg}. Check config in '{self.server_config_file}'."
            )

        config = configparser.ConfigParser()

        try:
            config.read(self.server_config_file)
            if not config.sections():
                _error("No server definition defined")

            server_name = (
                server_name
                or config.get(config.default_section, "default", fallback=None)
                or config.sections()[0]
            )
            host = config.get(server_name, "host")
            port = config.getint(server_name, "port")
            soap_path = config.get(server_name, "soap_path")
            webdesign_path = config.get(server_name, "webdesign_path")
            puakma_db_conn_id = config.getint(server_name, "puakma_db_conn_id")
            username = config.get(server_name, "username", fallback=None)
            password = config.get(server_name, "password", fallback=None)

            if not host:
                raise ValueError(f"Empty 'host' value for server '{server_name}'")
            if not soap_path:
                raise ValueError(f"Empty 'soap_path' value for server '{server_name}'")
            if not webdesign_path:
                raise ValueError(
                    f"Empty 'webdesign_path' value for server '{server_name}'"
                )

            return PuakmaServer(
                host,
                port,
                soap_path,
                webdesign_path,
                puakma_db_conn_id,
                username,
                password,
            )
        except (configparser.Error, ValueError) as e:
            _error(f"Error reading server from config: {str(e)}")

    def update_vscode_settings(self: Workspace, reset: bool = False) -> None:
        """
        Updates or creates the vortex.code-workspace file inside the .vscode directory
        """

        def _reset() -> dict[Any, Any]:
            if not self.vscode_dir.exists():
                self.vscode_dir.mkdir()
            return {}

        if reset:
            workspace_settings = _reset()
        else:
            try:
                with open(self.code_workspace_file) as f:
                    workspace_settings = json.load(f)
            except FileNotFoundError:
                workspace_settings = _reset()
            except json.JSONDecodeError as e:
                logger.error(f"Error parsing {self.code_workspace_file}: {e}")
                return

        # Folder settings
        vortex_dirs = [self.vscode_dir, self.config_dir]
        if self.logs_dir.is_dir():
            vortex_dirs.append(self.logs_dir)
        workspace_folders = [
            os.path.join("..", dir.name) for dir in (*vortex_dirs, *self.listdir())
        ]
        folder_settings = {
            "folders": [{"path": folder} for folder in workspace_folders]
        }

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

        with open(self.code_workspace_file, "w") as f:
            json.dump(workspace_settings, f, indent=2)
        status = "Reset" if reset else "Updated"
        logger.debug(f"{status} settings in '{self.code_workspace_file}'")

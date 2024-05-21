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

from vortex.models import DesignObject
from vortex.models import DesignObjectNotFound
from vortex.models import DesignType
from vortex.models import PuakmaApplication
from vortex.models import PuakmaServer
from vortex.util import file_lock

logger = logging.getLogger("vortex")

SAMPLE_CONFIG = """\
[dev]
host =
port = 80
username =
password =
soap_path = system/SOAPDesigner.pma
web_design_path = system/webdesign.pma
puakma_db_conn_id =
lib_path =
java_home =
java_environment_name =
"""


class WorkspaceError(Exception):
    pass


class WorkspaceInUseError(WorkspaceError):
    pass


class ServerConfigError(WorkspaceError):
    pass


class PuakmaApplicationNotFound(WorkspaceError):
    pass


class _CaseInsensitiveDict(dict[Any, Any]):
    def __getitem__(self, key: Any) -> Any:
        return super().__getitem__(key.lower())

    def __setitem__(self, key: Any, value: Any) -> Any:
        super().__setitem__(key.lower(), value)

    def __contains__(self, key: Any) -> Any:
        return super().__contains__(key.lower())


class Workspace:
    ENV_VAR = "VORTEX_HOME"

    def __init__(self, path: str | None = None, init: bool = False) -> None:
        self._path = Path(path or Workspace.get_default_workspace()).resolve()
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
        with the format 'host/group/name' inside the workspace.
        Returns the full path to the new app directory
        """
        full_path = self.path / app.path
        if full_path.exists() and force_recreate:
            shutil.rmtree(full_path)
        full_path.mkdir(exist_ok=True, parents=True)
        with open(full_path / app.MANIFEST_FILE, "wb") as f:
            pickle.dump(app, f)
        return full_path

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
        pattern = "**/.pma"
        if server:
            pattern = f"{server.host}/**/.pma"
        for app_file in self.path.glob(pattern):
            app_dir = app_file.parent
            if strict:
                try:
                    PuakmaApplication.from_dir(app_dir)
                except ValueError:
                    continue
            ret.append(app_dir)
        return ret

    def lookup_design_obj(
        self, server: PuakmaServer, design_obj_id: int
    ) -> tuple[int, DesignObject]:
        for app in self.listapps(server):
            try:
                return app.lookup_design_obj(design_obj_id=design_obj_id)
            except DesignObjectNotFound:
                pass
        raise DesignObjectNotFound(
            f"No Design Object Found with ID '{design_obj_id}' in locally cloned apps."
        )

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

    def set_config(self, section: str, option: str, value: str) -> None:
        config = configparser.ConfigParser(dict_type=_CaseInsensitiveDict)
        config.read(self.server_config_file)
        config[section.upper()][option.casefold()] = value
        with open(self.server_config_file, "w") as f:
            config.write(f)

    def listapps(self, server: PuakmaServer | None = None) -> list[PuakmaApplication]:
        return [PuakmaApplication.from_dir(dir) for dir in self.listdir(server)]

    def list_servers(self) -> list[str]:
        config = configparser.ConfigParser()
        config.read(self.server_config_file)
        return config.sections()

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
                server_name,
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

    def update_vscode_settings(
        self, server: PuakmaServer | None = None, reset: bool = False
    ) -> None:
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
        folders = [{"path": str(dir)} for dir in vortex_dirs]
        folders.extend(
            [
                {
                    "path": str(dir),
                    "name": str(PuakmaApplication.from_dir(dir)),
                }
                for dir in self.listdir(server)
            ]
        )
        folder_settings = {"folders": folders}

        # Java project settings
        settings: dict[str, Any] = workspace_settings.get("settings", {})
        puakma_path = os.path.join(os.path.dirname(__file__), "lib", "puakma.jar")
        referenced_libs = [puakma_path, os.path.join("zlib", "**", "*.jar")]
        java_runtimes: list[dict[str, Any]] = [{}]
        if server is not None:
            config = configparser.ConfigParser()
            config.read(self.server_config_file)
            server_libs = config.get(server.name, "lib_path", fallback=None)
            if server_libs:
                referenced_libs.extend(server_libs.split(","))
            java_home = config.get(server.name, "java_home", fallback=None)
            java_environment_name = config.get(
                server.name, "java_environment_name", fallback=None
            )
            if java_home and java_environment_name:
                java_runtimes = [
                    {"default": True, "path": java_home, "name": java_environment_name}
                ]

        java_project_settings = {
            "java.project.sourcePaths": DesignType.source_dirs(),
            "java.project.outputPath": "zbin",
            "java.project.referencedLibraries": referenced_libs,
            "java.configuration.runtimes": java_runtimes,
        }
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

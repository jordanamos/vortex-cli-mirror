from __future__ import annotations

import configparser
import contextlib
import logging
import os
import pickle
import shutil
from collections.abc import Generator
from pathlib import Path
from typing import NoReturn

import platformdirs

from vortex.models import PuakmaApplication
from vortex.models import PuakmaServer
from vortex.util import file_lock

logger = logging.getLogger("vortex")


class WorkspaceConfigError(Exception):
    pass


class Workspace:
    WORKSPACE_ENV_VAR = "VORTEX_WORKSPACE"

    def __init__(
        self, directory: str | None = None, server_name: str | None = None
    ) -> None:
        self._directory = Path(directory or Workspace.get_default_workspace())
        if not self._directory.is_dir():
            raise NotADirectoryError(f"'{self._directory}' is not a valid directory")
        self._server = self._read_server_from_config(server_name)

    def __str__(self) -> str:
        return str(self._directory)

    @property
    def directory(self) -> Path:
        return self._directory

    @property
    def server(self) -> PuakmaServer:
        return self._server

    @property
    def config_file(self) -> Path:
        return self.directory / "vortex-server-config.ini"

    @property
    def vscode_directory(self) -> Path:
        return self.directory / ".vscode"

    @property
    def code_workspace_file(self) -> Path:
        return self.vscode_directory / "vortex.code-workspace"

    @classmethod
    def get_default_workspace(cls) -> str:
        default_dir = os.path.join(
            platformdirs.user_documents_dir(), "vortex-cli-workspace"
        )
        ret = os.getenv(cls.WORKSPACE_ENV_VAR, default_dir)
        return os.path.realpath(ret)

    @contextlib.contextmanager
    def exclusive_lock(self) -> Generator[None, None, None]:
        def _blocked_cb() -> NoReturn:
            raise OSError(f"The directory '{self.directory}' is already in use.")

        try:
            with file_lock(self.directory / ".lock", _blocked_cb):
                yield
        except OSError as e:
            logger.error(e)
            raise SystemExit

    def mkdir(self, app: PuakmaApplication) -> Path:
        """
        Creates a .PuakmaApplication.pickle file within a newly created app directory
        with the format 'host_group_name' inside the workspace.
        Returns the full path to the new app directory
        """
        app_path = self.directory / app.dir_name
        if app_path.exists():
            shutil.rmtree(app_path)
        app_path.mkdir()
        with open(app_path / app.PICKLE_FILE, "wb") as f:
            pickle.dump(app, f)
        return app_path

    def listdir(self) -> list[Path]:
        """
        Returns a list of directories that contain a parseable
        .PuakmaApplication.pickle file
        """

        ret = []
        for sub_dir in self.directory.iterdir():
            if sub_dir.is_dir():
                try:
                    PuakmaApplication.from_dir(sub_dir)
                    ret.append(sub_dir)
                except ValueError:
                    continue
        return ret

    def _read_server_from_config(self, server_name: str | None = None) -> PuakmaServer:
        def _error(msg: str) -> NoReturn:
            raise WorkspaceConfigError(f"{msg}. Check config in '{self.config_file}'")

        config = configparser.ConfigParser()

        try:
            config.read(self.config_file)
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
            puakma_db_conn_id = config.getint(server_name, "puakma_db_conn_id")
            username = config.get(server_name, "username", fallback=None)
            password = config.get(server_name, "password", fallback=None)
            if not host:
                raise ValueError(f"Empty 'host' value for server '{server_name}'")
            if not soap_path:
                raise ValueError(f"Empty 'soap_path' value for server '{server_name}'")

            return PuakmaServer(
                host, port, soap_path, puakma_db_conn_id, username, password
            )
        except (configparser.Error, ValueError) as e:
            _error(f"Error reading server from config: {str(e)}")

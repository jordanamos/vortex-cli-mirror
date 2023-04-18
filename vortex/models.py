from __future__ import annotations

import base64
import contextlib
import getpass
import logging
import mimetypes
import os
import pickle
from collections.abc import Generator
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import NamedTuple
from typing import TYPE_CHECKING

from requests import Session
from requests.auth import HTTPBasicAuth

from vortex.util import JavaClassVersion

if TYPE_CHECKING:
    from vortex.soap import DatabaseDesigner
    from vortex.soap import DownloadDesigner
    from vortex.workspace import Workspace

DESIGN_OBJECT_QUERY = """\
SELECT designbucketid AS id
    , name
    , designtype AS design_type
    , contenttype AS content_type
    , designdata AS design_data
    , designsource AS design_source
FROM designbucket
WHERE appid = %d
"""

PUAKMA_APPLICATION_QUERY = """\
SELECT appid AS id
    , appname AS name
    , appgroup AS group
    , inheritfrom AS inherit_from
    , templatename AS template_name
FROM application
%s
ORDER BY appgroup
    , appname
"""

JAVA_MIME_TYPES = ("application/java", "application/octet-stream", "application/javavm")

logger = logging.getLogger("vortex")

mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("text/plain", ".txt")
mimetypes.add_type("application/java", ".java")


class PuakmaServer(NamedTuple):
    host: str
    port: int
    soap_path: str
    puakma_db_conn_id: int
    username: str | None
    password: str | None

    @property
    def base_soap_url(self) -> str:
        return f"http://{self.host}:{self.port}/{self.soap_path}"

    @contextlib.contextmanager
    def session(self) -> Generator[Session, None, None]:
        user = self.username or input("Enter your Tornado Server username: ")
        password = self.password or getpass.getpass(
            "Enter your Tornado Server password: "
        )
        with contextlib.closing(Session()) as sess:
            sess.auth = HTTPBasicAuth(user, password)
            yield sess

    def fetch_all_apps(
        self,
        database_designer: DatabaseDesigner,
        name_filter: str,
        group_filter: str,
        show_inherited: bool,
    ) -> list[PuakmaApplication]:
        where = "WHERE 1=1"
        if not show_inherited:
            where += " AND (inheritfrom IS NULL OR inheritfrom = '')"
        if name_filter:
            where += f" AND LOWER(appname) LIKE '%{name_filter.lower()}%'"
        if group_filter:
            where += f" AND LOWER(appgroup) LIKE '%{group_filter.lower()}%'"

        resp = database_designer.execute_query(
            self.puakma_db_conn_id, PUAKMA_APPLICATION_QUERY % where
        )
        return [PuakmaApplication(**app, server=self) for app in resp]

    def __eq__(self, other: object) -> bool:
        if isinstance(other, self.__class__):
            return (
                self.host == other.host
                and self.port == other.port
                and self.puakma_db_conn_id == other.puakma_db_conn_id
            )
        return False


@dataclass
class PuakmaApplication:
    PICKLE_FILE = ".PuakmaApplication.pickle"

    id: int
    name: str
    group: str
    inherit_from: str
    template_name: str
    server: PuakmaServer
    java_class_version: JavaClassVersion | None = None

    @property
    def dir_name(self) -> str:
        return f"{self.server.host}_{self.group}_{self.name}"

    @classmethod
    def from_dir(cls, path: Path | str) -> PuakmaApplication:
        """
        Returns an instance of this class from the .PuakmaApplication.pickle file
        within the given directory.
        Raises ValueError if unsuccessful
        """
        app_file = os.path.join(path, cls.PICKLE_FILE)
        try:
            with open(app_file, "rb") as f:
                app = pickle.load(f)
            if isinstance(app, cls):
                return app
            else:
                raise ValueError(f"Unexpected instance {type(app)}")
        except (FileNotFoundError, pickle.UnpicklingError, ValueError) as e:
            raise ValueError(f"Error initialising {cls}: {e}")

    def fetch_design_object(
        self, database_designer: DatabaseDesigner, design_name: str
    ) -> DesignObject:
        """
        Returns a single Design Object from a design name and app id.
        Raises ValueError if:
            - the object doesnt exist
            - if it is ambiguous
            - if the design type cannot be parsed as a valid DesignType
        """

        query = f"{DESIGN_OBJECT_QUERY} AND name = '%s'" % (self.id, design_name)
        query_result = database_designer.execute_query(
            self.server.puakma_db_conn_id, query
        )
        if not query_result:
            raise ValueError(
                f"Application [{self.id}] has no Design Object '{design_name}'"
            )
        elif len(query_result) != 1:
            raise ValueError(f"Design Object '{design_name}' is ambiguos")
        obj = query_result.pop()
        return DesignObject(
            int(obj["id"]),
            obj["name"],
            DesignType(int(obj["design_type"])),
            obj["content_type"],
            obj["design_data"],
            obj["design_source"],
            self,
        )

    def fetch_all_design_objects(
        self, database_designer: DatabaseDesigner, get_resources: bool = False
    ) -> list[DesignObject]:
        resources_where = (
            "" if get_resources else f" AND designtype <> {DesignType.RESOURCE.value}"
        )
        query = f"{DESIGN_OBJECT_QUERY}{resources_where}" % self.id

        result = database_designer.execute_query(self.server.puakma_db_conn_id, query)
        design_objs: list[DesignObject] = []
        for obj in result:
            try:
                design_objs.append(
                    DesignObject(
                        int(obj["id"]),
                        obj["name"],
                        DesignType(int(obj["design_type"])),
                        obj["content_type"],
                        obj["design_data"],
                        obj["design_source"],
                        self,
                    )
                )
            except ValueError as e:
                logger.warning(
                    f"Unable to save Design Object '{obj['name']}' [{obj['id']}]: {e}"
                )
        return design_objs


@dataclass
class DesignObject:
    id: int
    name: str
    design_type: DesignType
    content_type: str
    design_data: str
    design_source: str
    app: PuakmaApplication
    is_jar_library: bool = False
    package: str | None = None

    @property
    def file_ext(self) -> str | None:
        ext = mimetypes.guess_extension(self.content_type)
        if self.content_type in JAVA_MIME_TYPES:
            ext = ".java"
        return ext

    @property
    def file_name(self) -> str:
        return self.name + self.file_ext if self.file_ext else self.name

    @property
    def design_dir(self) -> str:
        if self.is_jar_library:
            return "zlib"
        dir_name = self.design_type.name
        if self.design_type.is_java_type and self.package:
            dir_name = os.path.join(dir_name, self.package)
        return dir_name

    def set_data(self, path: DesignPath, set_source: bool) -> None:
        with open(path, "rb") as f:
            file_bytes = f.read()
        base64data = str(base64.b64encode(file_bytes), "utf-8")
        if set_source:
            self.design_source = base64data
        else:
            self.design_data = base64data

    def design_path(self, workspace: Workspace) -> DesignPath:
        return DesignPath(
            workspace,
            os.path.join(
                workspace.directory,
                self.app.dir_name,
                self.design_dir,
                self.file_name,
            ),
        )

    def upload(
        self, download_designer: DownloadDesigner, do_source: bool = False
    ) -> bool:
        data = self.design_source if do_source else self.design_data
        return download_designer.upload_design(self.id, data, do_source)

    def save(self, workspace: Workspace) -> None:
        data = self.design_data
        if self.design_type.is_java_type and not self.is_jar_library:
            data = self.design_source
        data_bytes = base64.b64decode(data, validate=True)
        design_path = self.design_path(workspace)
        design_path.path.parent.mkdir(parents=True, exist_ok=True)
        with open(design_path, "wb") as f:
            f.write(data_bytes)

    def __str__(self) -> str:
        return f"'{self.name}' [{self.id}]"


class DesignType(Enum):
    PAGE = 1
    RESOURCE = 2
    ACTION = 3
    SHARED_CODE = 4
    SCHEDULED_ACTION = 6
    WIDGET = 7

    @property
    def is_java_type(self) -> bool:
        return self in self.java_types()

    @classmethod
    def from_name(cls, name: str) -> DesignType:
        for member in cls:
            if member.name == name:
                return cls(member.value)
        raise ValueError(f"'{name}' is not a valid DesignType")

    @classmethod
    def java_types(cls) -> tuple[DesignType, ...]:
        return (
            cls.ACTION,
            cls.SHARED_CODE,
            cls.SCHEDULED_ACTION,
            cls.WIDGET,
        )

    @classmethod
    def source_dirs(cls) -> tuple[str, ...]:
        return tuple(java_type.name for java_type in cls.java_types())


class DesignPath:
    """
    Represents a path to a Design Object.
    The path should be the full path to the object
    Raises ValueError if:
        - the app_directory is not valid
        - the path is not in the expected format
    """

    def __init__(self, workspace: Workspace, path: str) -> None:
        try:
            rel_path = os.path.relpath(path, workspace.directory)
            app_dir, design_type_dir, _remaining = rel_path.split(
                os.path.sep, maxsplit=2
            )
            app_dir = os.path.join(workspace.directory, app_dir)
            # the app directory should always exist *before* instantiating this object
            self.app = PuakmaApplication.from_dir(app_dir)
        except ValueError:
            raise ValueError(f"Invalid path to a Design Object '{path}'")

        self.path = Path(path)
        self.rel_path = rel_path
        self.app_dir = app_dir
        self.design_type_dir = design_type_dir
        self.file_name = os.path.basename(path)
        self.design_name, self.file_ext = os.path.splitext(self.file_name)

    def __str__(self) -> str:
        return str(self.path)

    def __fspath__(self) -> str:
        return str(self.path)

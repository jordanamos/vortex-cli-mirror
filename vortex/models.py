from __future__ import annotations

import base64
import contextlib
import getpass
import logging
import mimetypes
import os
import pickle
from collections.abc import AsyncGenerator
from collections.abc import Generator
from dataclasses import dataclass
from enum import Enum
from io import StringIO
from pathlib import Path
from typing import NamedTuple
from typing import TYPE_CHECKING

import httpx

from vortex.util import VERSION

if TYPE_CHECKING:
    from vortex.soap import DatabaseDesigner
    from vortex.soap import DownloadDesigner
    from vortex.workspace import Workspace

mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("text/plain", ".txt")
mimetypes.add_type("application/java", ".java")

logger = logging.getLogger("vortex")


_DESIGN_OBJECT_QUERY = """\
SELECT designbucketid AS id
    , name
    , designtype AS design_type
    , contenttype AS content_type
    , designdata AS design_data
    , designsource AS design_source
FROM designbucket
WHERE appid = %d
"""

_PUAKMA_APPLICATION_QUERY = """\
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

_JAVA_MIME_TYPES = (
    "application/java",
    "application/octet-stream",
    "application/javavm",
)
_USER_AGENT = f"vortex-cli/{VERSION}"


JavaClassVersion = tuple[int, int]


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

    @property
    def base_webdesign_url(self) -> str:
        return f"http://{self.host}/system/webdesign.pma"

    @contextlib.contextmanager
    def connect(self) -> Generator[httpx.Client, None, None]:
        user = self.username or input("Enter your Username: ")
        password = self.password or getpass.getpass("Enter your Password: ")
        headers = {"user-agent": _USER_AGENT}
        auth = (user, password)
        with contextlib.closing(httpx.Client(auth=auth, headers=headers)) as sess:
            yield sess

    @contextlib.asynccontextmanager
    async def aconnect(self) -> AsyncGenerator[httpx.AsyncClient, None]:
        user = self.username or input("Enter your Username: ")
        password = self.password or getpass.getpass("Enter your Password: ")
        headers = {"user-agent": _USER_AGENT}
        auth = (user, password)
        async with contextlib.aclosing(
            httpx.AsyncClient(auth=auth, headers=headers)
        ) as sess:
            yield sess

    def fetch_all_apps(
        self,
        database_designer: DatabaseDesigner,
        name_filter: str,
        group_filter: str,
        template_filter: str,
        show_inherited: bool,
    ) -> list[PuakmaApplication]:
        where = StringIO()
        where.write("WHERE 1=1")
        if not show_inherited:
            where.write(" AND (inheritfrom IS NULL OR inheritfrom = '')")
        if name_filter:
            where.write(f" AND LOWER(appname) LIKE '%{name_filter.lower()}%'")
        if group_filter:
            where.write(f" AND LOWER(appgroup) LIKE '%{group_filter.lower()}%'")
        if template_filter:
            where.write(f" AND LOWER(templatename) LIKE '%{template_filter.lower()}%'")

        query = _PUAKMA_APPLICATION_QUERY % where.getvalue()
        where.close()
        resp = database_designer.execute_query(self.puakma_db_conn_id, query)

        return [PuakmaApplication(**app, server=self) for app in resp]

    def __eq__(self, other: object) -> bool:
        if isinstance(other, PuakmaServer):
            return (
                self.host == other.host
                and self.port == other.port
                and self.puakma_db_conn_id == other.puakma_db_conn_id
            )
        return False

    def __ne__(self, other: object) -> bool:
        if isinstance(other, PuakmaServer):
            return not (
                self.host == other.host
                and self.port == other.port
                and self.puakma_db_conn_id == other.puakma_db_conn_id
            )
        return True

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"


class PuakmaApplication:
    PICKLE_FILE = ".PuakmaApplication.pickle"

    def __init__(
        self,
        id: int,
        name: str,
        group: str,
        inherit_from: str,
        template_name: str,
        server: PuakmaServer,
        java_class_version: JavaClassVersion | None = None,
    ) -> None:
        self.id = id
        self.name = name
        self.group = group
        self.inherit_from = inherit_from
        self.template_name = template_name
        self.server = server
        self.java_class_version = java_class_version
        self._design_objects: tuple[DesignObject, ...] = tuple()

    @property
    def dir_name(self) -> str:
        return f"{self.server.host}_{self.group}_{self.name}"

    @property
    def url(self) -> str:
        return f"http://{self.server.host}/{self.group}/{self.name}.pma"

    @property
    def web_design_url(self) -> str:
        return f"{self.server.base_webdesign_url}/DesignList?OpenPage&AppID={self.id}"

    @property
    def design_objects(self) -> tuple[DesignObject, ...]:
        return self._design_objects

    @design_objects.setter
    def design_objects(self, value: tuple[DesignObject]) -> None:
        self._design_objects = tuple(value)

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

    def lookup_design_obj(self, design_name: str) -> list[DesignObject]:
        return [obj for obj in self.design_objects if obj.name == design_name]

    def fetch_design_objects(
        self, database_designer: DatabaseDesigner, get_resources: bool = False
    ) -> list[DesignObject]:
        resources_where = (
            "" if get_resources else f" AND designtype <> {DesignType.RESOURCE.value}"
        )
        query = f"{_DESIGN_OBJECT_QUERY}{resources_where}" % self.id

        result = database_designer.execute_query(self.server.puakma_db_conn_id, query)
        design_objs: list[DesignObject] = []

        for obj in result:
            design_type_id = int(obj["design_type"])
            design_name = obj["name"]

            try:
                design_type = DesignType(design_type_id)
            except ValueError:
                logger.debug(
                    f"Skipped Design Object '{design_name}' [{obj['id']}]: "
                    f"Invalid Design Type [{design_type_id}]"
                )
            else:
                design_objs.append(
                    DesignObject(
                        int(obj["id"]),
                        design_name,
                        design_type,
                        obj["content_type"],
                        obj["design_data"],
                        obj["design_source"],
                        self,
                    )
                )
        return design_objs

    def __str__(self) -> str:
        return f"{self.group}/{self.name}"


@dataclass(slots=True)
class DesignObject:
    id: int
    name: str
    design_type: DesignType
    content_type: str
    _design_data: str
    _design_source: str
    app: PuakmaApplication
    is_jar_library: bool = False
    package: str | None = None

    @property
    def design_data(self) -> bytes:
        return base64.b64decode(self._design_data, validate=True)

    @design_data.setter
    def design_data(self, value: bytes) -> None:
        self._design_data = str(base64.b64encode(value), "utf-8")

    @property
    def design_source(self) -> bytes:
        return base64.b64decode(self._design_source, validate=True)

    @design_source.setter
    def design_source(self, value: bytes) -> None:
        self._design_source = str(base64.b64encode(value), "utf-8")

    @property
    def file_ext(self) -> str | None:
        ext = mimetypes.guess_extension(self.content_type)
        if self.content_type in _JAVA_MIME_TYPES:
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

    @property
    def do_save_source(self) -> bool:
        return self.design_type.is_java_type and not self.is_jar_library

    def get_design_path(self, workspace: Workspace) -> DesignPath:
        return DesignPath(
            workspace,
            os.path.join(
                workspace.path,
                self.app.dir_name,
                self.design_dir,
                self.file_name,
            ),
        )

    async def upload(
        self, download_designer: DownloadDesigner, upload_source: bool = False
    ) -> bool:
        data = self._design_source if upload_source else self._design_data
        return await download_designer.aupload_design(self.id, data, upload_source)

    def save(self, workspace: Workspace) -> None:
        data_bytes = self.design_data
        if self.do_save_source:
            data_bytes = self.design_source
        design_path = self.get_design_path(workspace)
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
    # DOCUMENTATION = 5 This appears to use source rather than data >.<
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


class InvalidDesignPathError(Exception):
    pass


class DesignPath:
    """
    Represents a path to a Design Object.
    The path should be the full path to the object
    Raises InvalidDesignPathError if:
        - the app_directory is not valid
        - the path is not in the expected format
    """

    def __init__(self, workspace: Workspace, path: str) -> None:
        try:
            rel_path = os.path.relpath(path, workspace.path)
            app_dir, design_type_dir, _remaining = rel_path.split(
                os.path.sep, maxsplit=2
            )
            app_dir = os.path.join(workspace.path, app_dir)
            self.app = PuakmaApplication.from_dir(app_dir)
        except ValueError:
            raise InvalidDesignPathError(f"Invalid path to a Design Object '{path}'")

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

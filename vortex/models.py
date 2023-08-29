from __future__ import annotations

import base64
import getpass
import logging
import mimetypes
import os
import pickle
from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from enum import IntEnum
from io import StringIO
from pathlib import Path
from types import TracebackType
from typing import Literal
from typing import NamedTuple
from typing import TYPE_CHECKING

import httpx

from vortex.soap import AppDesigner
from vortex.soap import DatabaseDesigner
from vortex.soap import DownloadDesigner
from vortex.soap import ServerDesigner

if TYPE_CHECKING:
    from vortex.workspace import Workspace

mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("text/plain", ".txt")
mimetypes.add_type("application/java", ".java")

logger = logging.getLogger("vortex")

_JAVA_MIME_TYPES = (
    "application/java",
    "application/octet-stream",
    "application/javavm",
)

_DESIGN_OBJECT_QUERY = """\
SELECT designbucketid AS id
    , name
    , designtype AS type
    , contenttype AS ctype
    , designdata AS data
    , designsource AS src
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

_LOGS_QUERY = """\
SELECT logid AS id
    , logstring AS msg
    , logdate AS date
    , type
    , source AS src
    , username AS user
FROM pmalog
WHERE type <> 'I'
ORDER BY logdate DESC
LIMIT % d
"""

_ACTION_TEMPLATE = """\
import puakma.system.ActionRunner;

public class %s extends ActionRunner {

    public String execute() {
        return "";
    }
}
"""

_SHARED_CODE_TEMPLATE = """\
public class %s {

}
"""

JavaClassVersion = tuple[int, int]


class LogItem(NamedTuple):
    id: int
    msg: str
    date: datetime
    type: str
    item_source: str
    username: str


class PuakmaServer:
    def __init__(
        self,
        host: str,
        port: int,
        soap_path: str,
        puakma_db_conn_id: int,
        username: str | None = None,
        password: str | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self.soap_path = soap_path
        self.puakma_db_conn_id = puakma_db_conn_id
        self.username = username or input("Enter your Username: ")
        self.password = password or getpass.getpass("Enter your Password: ")

        self._aclient = httpx.AsyncClient(auth=self.auth)
        self._client = httpx.Client(auth=self.auth)

        self.app_designer = AppDesigner(self)
        self.database_designer = DatabaseDesigner(self)
        self.download_designer = DownloadDesigner(self)
        self.server_designer = ServerDesigner(self)

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    @property
    def auth(self) -> tuple[str, str]:
        return self.username, self.password

    @property
    def base_soap_url(self) -> str:
        return f"{self}/{self.soap_path}"

    def __str__(self) -> str:
        return f"http://{self.host}:{self.port}"

    def __enter__(self) -> PuakmaServer:
        return self

    async def __aenter__(self) -> PuakmaServer:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None = None,
    ) -> Literal[False]:
        await self._aclient.aclose()
        return False

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None = None,
    ) -> Literal[False]:
        self._client.close()
        return False

    def fetch_all_apps(
        self,
        name_filter: list[str],
        group_filter: list[str],
        template_filter: list[str],
        show_inherited: bool,
    ) -> list[PuakmaApplication]:
        where = StringIO()
        where.write("WHERE 1=1")

        def _or(field: str, values: list[str]) -> None:
            where.write("AND (")
            for i, val in enumerate(values):
                if i > 0:
                    where.write(" OR ")
                where.write(f"LOWER({field}) LIKE '%{val.lower()}%'")
            where.write(")")

        if not show_inherited:
            where.write(" AND (inheritfrom IS NULL OR inheritfrom = '')")
        if name_filter:
            _or("appname", name_filter)
        if group_filter:
            _or("appgroup", group_filter)
        if template_filter:
            _or("templatename", template_filter)

        query = _PUAKMA_APPLICATION_QUERY % where.getvalue()
        where.close()
        resp = self.database_designer.execute_query(self.puakma_db_conn_id, query)
        return [PuakmaApplication(**app, host=self.host) for app in resp]

    def get_last_log_items(self, limit_items: int = 10) -> list[LogItem]:
        limit_items = min(max(limit_items, 1), 50)
        query = _LOGS_QUERY % limit_items
        log_date_format = "%Y-%m-%d %H:%M:%S.%f"
        resp = self.database_designer.execute_query(self.puakma_db_conn_id, query)
        logs: list[LogItem] = []
        for log in resp:
            id_ = int(log["id"])
            date = datetime.strptime(log["date"], log_date_format)
            log_ = LogItem(id_, log["msg"], date, log["type"], log["src"], log["user"])
            logs.append(log_)
        return logs


class PuakmaApplication:
    PICKLE_FILE = ".PuakmaApplication.pickle"

    def __init__(
        self,
        id: int,
        name: str,
        group: str,
        inherit_from: str,
        template_name: str,
        host: str,
        java_class_version: JavaClassVersion | None = None,
    ) -> None:
        self.id = id
        self.name = name
        self.group = group
        self.inherit_from = inherit_from
        self.template_name = template_name
        self.host = host
        self.java_class_version = java_class_version
        self.design_objects: list[DesignObject] = []

    @property
    def dir_name(self) -> str:
        return f"{self.host}_{self.group}_{self.name}"

    @property
    def url(self) -> str:
        return f"http://{self.host}/{self.group}/{self.name}.pma"

    @property
    def web_design_url(self) -> str:
        base_url = f"http://{self.host}/system/webdesign.pma"
        return f"{base_url}/DesignList?OpenPage&AppID={self.id}"

    def __str__(self) -> str:
        return f"{self.group}/{self.name}"

    @classmethod
    def from_dir(cls, path: Path) -> PuakmaApplication:
        """
        Returns an instance of this class from the .PuakmaApplication.pickle file
        within the given directory.
        Raises ValueError if unsuccessful
        """
        app_file = path / cls.PICKLE_FILE
        try:
            with open(app_file, "rb") as f:
                app = pickle.load(f)
            if not isinstance(app, cls):
                raise TypeError(f"Unexpected instance of type {type(app)}")
        except Exception as e:
            raise ValueError(f"Error initialising {cls}: {e}")
        else:
            return app

    def fetch_design_objects(
        self, server: PuakmaServer, get_resources: bool = False
    ) -> list[DesignObject]:
        resources_where = (
            "" if get_resources else f" AND designtype <> {DesignType.RESOURCE.value}"
        )
        query = f"{_DESIGN_OBJECT_QUERY}{resources_where}" % self.id
        result = server.database_designer.execute_query(server.puakma_db_conn_id, query)
        objs: list[DesignObject] = []
        for obj in result:
            design_type_id = int(obj["type"])
            name = obj["name"]
            id_ = int(obj["id"])
            try:
                type_ = DesignType(design_type_id)
            except ValueError:
                logger.debug(
                    f"Skipped Design Object '{name}' [{obj['id']}]: "
                    f"Invalid Design Type [{design_type_id}]"
                )
                continue
            objs.append(
                DesignObject(
                    id_, name, type_, obj["ctype"], obj["data"], obj["src"], self
                )
            )
        return objs

    def lookup_design_obj(self, design_name: str) -> dict[int, DesignObject]:
        """Returns {index: obj} for each match in the design_objects list"""
        return {
            i: obj
            for i, obj in enumerate(self.design_objects)
            if obj.name == design_name
        }


@dataclass(slots=True, order=True)
class DesignObject:
    sort_index: str = field(init=False)
    id: int
    name: str
    design_type: DesignType
    content_type: str
    _design_data: str = field(repr=False)
    _design_source: str = field(repr=False)
    app: PuakmaApplication
    is_jar_library: bool = False
    package_dir: Path | None = None
    open_action: str | None = None
    save_action: str | None = None
    comment: str | None = None
    inherit_from: str | None = None

    def __post_init__(self) -> None:
        self.sort_index = self.name.casefold()

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
    def design_dir(self) -> Path:
        if self.is_jar_library:
            return Path("zlib")
        dir_name = Path(self.design_type.name)
        if self.design_type.is_java_type and self.package_dir:
            dir_name /= self.package_dir
        return dir_name

    @property
    def do_save_source(self) -> bool:
        return self.design_type.is_java_type and not self.is_jar_library

    def design_path(self, workspace: Workspace) -> DesignPath:
        return DesignPath(
            workspace,
            workspace.path / self.app.dir_name / self.design_dir / self.file_name,
        )

    async def aupload(
        self, download_designer: DownloadDesigner, upload_source: bool = False
    ) -> bool:
        data = self._design_source if upload_source else self._design_data
        return await download_designer.aupload_design(self.id, data, upload_source)

    def save(self, workspace: Workspace) -> None:
        data_bytes = self.design_data
        if self.do_save_source:
            data_bytes = self.design_source
        design_path = self.design_path(workspace)
        design_path.path.parent.mkdir(parents=True, exist_ok=True)
        with open(design_path, "wb") as f:
            f.write(data_bytes)

    def __str__(self) -> str:
        return f"'{self.name}' [{self.id}]"


class DesignType(IntEnum):
    PAGE = 1
    RESOURCE = 2
    ACTION = 3
    SHARED_CODE = 4
    # This appears to use source rather than data >.<
    # DOCUMENTATION = 5
    SCHEDULED_ACTION = 6
    WIDGET = 7

    @property
    def is_java_type(self) -> bool:
        return self in self.java_types()

    def source_template(self, name: str) -> str:
        ret = (_ACTION_TEMPLATE % name) if self.is_java_type else ""
        if self == DesignType.SHARED_CODE:
            ret = _SHARED_CODE_TEMPLATE % name
        return ret

    @classmethod
    def from_name(cls, name: str) -> DesignType:
        for member in cls:
            if member.name.lower() == name.lower():
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
    Represents a path to a Design Object. Expects format:
    /path/to/workspace/app_dir/design_dir/.../obj
    otherwise a InvalidDesignPathError is raised
    """

    def __init__(self, workspace: Workspace, path: Path) -> None:
        try:
            rel_path = path.relative_to(workspace.path)
            app_dir, design_dir, _rem = str(rel_path).split(os.path.sep, maxsplit=2)
            app_path = workspace.path / app_dir
            self.app = PuakmaApplication.from_dir(app_path)
        except ValueError as e:
            raise InvalidDesignPathError(f"Invalid path to Design Object '{path}': {e}")

        self.workspace = workspace
        self.path = path
        self.app_dir_path = app_path
        self.design_dir = design_dir
        self.fname = path.name
        self.design_name, self.ext = os.path.splitext(self.fname)

    def __str__(self) -> str:
        return str(self.path)

    def __fspath__(self) -> str:
        return str(self.path)

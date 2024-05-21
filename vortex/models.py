from __future__ import annotations

import asyncio
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
from typing import Any
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

logger = logging.getLogger("vortex")

_DEFAULT_JAVA_TYPE = "application/java"

mimetypes.add_type("text/javascript", ".js")
mimetypes.add_type("text/plain", ".txt")
mimetypes.add_type(_DEFAULT_JAVA_TYPE, ".java")


_JAVA_MIME_TYPES = (
    _DEFAULT_JAVA_TYPE,
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
SELECT app.appid AS id
    , appname AS name
    , appgroup AS group
    , inheritfrom AS inherit_from
    , templatename AS template_name
FROM application app
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
%s
ORDER BY logdate DESC
LIMIT %d
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


class DesignObjectAmbiguousError(Exception):
    pass


class DesignObjectNotFound(Exception):
    pass


class LogItem(NamedTuple):
    id: int
    msg: str
    date: datetime
    type: str
    item_source: str
    username: str


class DatabaseConnection(NamedTuple):
    id: int
    name: str


class PuakmaServer:
    def __init__(
        self,
        name: str,
        host: str,
        port: int,
        soap_path: str,
        webdesign_path: str,
        puakma_db_conn_id: int,
        username: str | None = None,
        password: str | None = None,
    ) -> None:
        self.name = name
        self._host = host
        self._port = port
        self.soap_path = soap_path
        self.webdesign_path = webdesign_path
        self.puakma_db_conn_id = puakma_db_conn_id
        self.username = (
            username or os.getenv("VORTEX_USERNAME") or input("Enter your Username: ")
        )
        self.password = (
            password
            or os.getenv("VORTEX_PASSWORD")
            or getpass.getpass("Enter your Password: ")
        )
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

    @property
    def base_webdesign_url(self) -> str:
        return f"{self}/{self.webdesign_path}"

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
        strict_search: bool,
        get_inherited: bool,
        get_inactive: bool,
    ) -> list[PuakmaApplication]:
        def _and_or(field: str, values: list[str]) -> None:
            where.write("AND (")
            for i, val in enumerate(values):
                if i > 0:
                    where.write(" OR ")
                if strict_search:
                    where.write(f"{field} = '{val}'")
                else:
                    where.write(f"LOWER({field}) LIKE '%{val.lower()}%'")
            where.write(")")

        where = StringIO()
        where.write("WHERE 1=1")
        if not get_inherited:
            where.write(" AND (inheritfrom IS NULL OR inheritfrom = '')")
        if name_filter:
            _and_or("appname", name_filter)
        if group_filter:
            _and_or("appgroup", group_filter)
        if template_filter:
            _and_or("templatename", template_filter)
        if not get_inactive:
            where.write(
                " AND NOT EXISTS (SELECT 1 FROM appparam ap"
                " WHERE ap.appid=app.appid AND paramname='DisableApp'"
                " AND paramvalue='1')"
            )

        query = _PUAKMA_APPLICATION_QUERY % where.getvalue()
        where.close()
        resp = self.database_designer.execute_query(self.puakma_db_conn_id, query)
        return [PuakmaApplication(**app, host=self.host) for app in resp]

    def get_last_log_items(
        self,
        limit_items: int,
        source_filter: str | None,
        messsage_filter: str | None,
        errors_only: bool,
        info_only: bool,
        debug_only: bool,
        last_log_item_id: int | None = None,
    ) -> list[LogItem]:
        def _and(field: str, val: str) -> None:
            where.write(f" AND (LOWER({field}) LIKE '%{val.lower()}%')")

        where = StringIO()
        where.write("WHERE 1=1")
        if source_filter:
            _and("source", source_filter)
        if messsage_filter:
            _and("logstring", messsage_filter)
        if last_log_item_id is not None and last_log_item_id > 0:
            where.write(f" AND logid > {last_log_item_id}")
        if errors_only:
            where.write(" AND (type = 'E')")
        elif info_only:
            where.write(" AND (type = 'I')")
        elif debug_only:
            where.write(" AND (type = 'D')")

        query = _LOGS_QUERY % (where.getvalue(), limit_items)
        where.close()
        log_date_format = "%Y-%m-%d %H:%M:%S.%f"
        resp = self.database_designer.execute_query(self.puakma_db_conn_id, query)
        logs: list[LogItem] = []
        for log in resp:
            id_ = int(log["id"])

            try:
                date = datetime.strptime(log["date"], log_date_format)
            except ValueError:
                # try No ms
                date = datetime.strptime(log["date"], "%Y-%m-%d %H:%M:%S")

            log_ = LogItem(id_, log["msg"], date, log["type"], log["src"], log["user"])
            logs.append(log_)
        return logs


class PuakmaApplication:
    MANIFEST_FILE = ".pma"

    def __init__(
        self,
        id: int,
        name: str,
        group: str,
        inherit_from: str | None,
        template_name: str | None,
        host: str,
        db_connections: tuple[DatabaseConnection, ...] | None = None,
        java_class_version: JavaClassVersion | None = None,
    ) -> None:
        self.id = id
        self.name = name
        self.group = group
        self.inherit_from = inherit_from
        self.template_name = template_name
        self.host = host
        self.java_class_version = java_class_version
        self.db_connections = db_connections
        self.design_objects: list[DesignObject] = []

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PuakmaApplication):
            return NotImplemented
        return self.host == other.host and self.id == other.id

    def __str__(self) -> str:
        return f"{self.group}/{self.name}"

    def __hash__(self) -> int:
        return hash((self.host, self.id))

    @property
    def path(self) -> Path:
        # the 'puakma' application doesn't have a group
        return Path(self.host, self.group or "_", self.name)

    @property
    def url(self) -> str:
        return f"http://{self.host}/{self.group}/{self.name}.pma"

    @property
    def web_design_url(self) -> str:
        base_url = f"http://{self.host}/system/webdesign.pma"
        return f"{base_url}/DesignList?OpenPage&AppID={self.id}"

    @classmethod
    def from_dir(cls, path: Path) -> PuakmaApplication:
        """
        Returns an instance of this class from the .PuakmaApplication.pickle file
        within the given directory.
        Raises ValueError if unsuccessful
        """
        app_file = path / cls.MANIFEST_FILE
        try:
            with open(app_file, "rb") as f:
                app = pickle.load(f)
            if not isinstance(app, cls):
                raise TypeError(f"Unexpected instance of type {type(app)}")
        except Exception as e:
            raise ValueError(f"Error initialising {cls}: {e}")
        else:
            return app

    @staticmethod
    async def afetch_design_objects(
        server: PuakmaServer, app_id: int, get_resources: bool = False
    ) -> list[dict[str, Any]]:
        resources_where = ""
        if not get_resources:
            resources_where = (
                f" AND (designtype <> {DesignType.RESOURCE.value}"
                " OR contenttype = 'application/java-archive')"
            )

        query = f"{_DESIGN_OBJECT_QUERY}{resources_where}" % app_id
        logger.debug(f"Fetching Design Objects [{app_id}]...")
        return await server.database_designer.aexecute_query(
            server.puakma_db_conn_id, query
        )

    def lookup_design_obj(
        self, design_name: str | None = None, *, design_obj_id: int | None = None
    ) -> tuple[int, DesignObject]:
        """Returns (index, obj) for the first match in the design_objects list."""
        if not design_name and not design_obj_id:
            raise ValueError(
                f"Argument design_name ({design_name}) and "
                f"design_obj_id ({design_obj_id}) can't both be None."
            )

        matches = [
            (i, obj)
            for i, obj in enumerate(self.design_objects)
            if obj.is_valid
            and (
                (design_name and obj.name == design_name)
                or (design_obj_id is not None and design_obj_id == obj.id)
            )
        ]

        if len(matches) > 1:
            _objs = ", ".join(str(obj[1]) for obj in matches)
            raise DesignObjectAmbiguousError(
                f"Design Object with name '{design_name}' is ambiguous: {_objs}"
            )
        if not matches:
            raise DesignObjectNotFound(
                f"No match found for design name '{design_name}'"
            )
        return matches.pop()


class DesignObjectParam(NamedTuple):
    name: str
    value: str


@dataclass(slots=True)
class DesignObject:
    id: int
    name: str
    app: PuakmaApplication = field(repr=False)
    _design_type: DesignType
    content_type: str = field(repr=False)
    _design_data: str = field(repr=False, default="")
    _design_source: str = field(repr=False, default="")
    is_jar_library: bool = field(repr=False, default=False)
    package_dir: Path | None = field(repr=False, default=None)
    comment: str | None = field(repr=False, default=None)
    inherit_from: str | None = field(repr=False, default=None)
    is_valid: bool = field(repr=False, default=True)
    # Params
    params: list[DesignObjectParam] = field(repr=False, default_factory=list)

    def __post_init__(self) -> None:
        if self.design_type == DesignType.ERROR:
            self.is_valid = False

    def __str__(self) -> str:
        return f"'{self.name}' [{self.id}]"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DesignObject):
            return NotImplemented
        return self.app.host == other.app.host and self.id == other.id

    def __hash__(self) -> int:
        return hash((self.app.host, self.id))

    @property
    def design_type(self) -> DesignType:
        return self._design_type

    @design_type.setter
    def design_type(self, value: DesignType) -> DesignType:
        if value == DesignType.ERROR:
            self.is_valid = False
        return self._design_type

    @property
    def open_action(self) -> str | None:
        return self.get_parameter_value("OpenAction")

    @property
    def save_action(self) -> str | None:
        return self.get_parameter_value("SaveAction")

    @property
    def parent_page(self) -> str | None:
        return self.get_parameter_value("ParentPage")

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
        ext = mimetypes.guess_extension(self.content_type.strip())
        if self.content_type.strip() in _JAVA_MIME_TYPES:
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
        return (
            self.design_type.is_java_type and not self.is_jar_library
        ) or self.design_type == DesignType.DOCUMENTATION

    def get_parameter_value(self, param_name: str) -> str | None:
        for param in self.params:
            if param.name.casefold() == param_name.casefold():
                return param.value
        return None

    def update_or_append_param(self, new_param: DesignObjectParam) -> None:
        for i, param in enumerate(self.params):
            if param.name.casefold() == new_param.name.casefold():
                # Update the value if the name exists
                self.params[i] = param._replace(value=new_param.value)
                break
        else:
            self.params.append(new_param)

    def design_path(self, workspace: Workspace) -> DesignPath:
        return DesignPath(
            workspace,
            workspace.path / self.app.path / self.design_dir / self.file_name,
        )

    async def aupload(
        self, download_designer: DownloadDesigner, upload_source: bool = False
    ) -> bool:
        data = self._design_source if upload_source else self._design_data
        ok = await download_designer.aupload_design(self.id, data, upload_source)
        upload_type = "SOURCE" if upload_source else "DATA"
        lvl, status = (logging.INFO, "OK") if ok else (logging.WARNING, "ERROR")
        msg = f"Upload {upload_type} of Design Object {self}: {status}"
        logger.log(lvl, msg)
        return ok

    async def acreate_or_update(self, app_designer: AppDesigner) -> bool:
        do_create = self.id < 0
        ret_id = await app_designer.aupdate_design_object(self)
        ok = ret_id > 0
        lvl, status = (logging.INFO, "OK") if ok else (logging.WARNING, "ERROR")
        msg = f"{'Created' if do_create else 'Updated'} Design Object {self}: {status}"
        logger.log(lvl, msg)
        if self.id == -1 and ok:
            self.id = ret_id
        return ok

    async def acreate_params(self, app_designer: AppDesigner) -> None:
        tasks = []
        for param in self.params:
            tasks.append(
                asyncio.create_task(
                    app_designer.aadd_design_object_param(
                        self.id, param.name, param.value
                    )
                )
            )
        await asyncio.gather(*tasks)

    async def adelete(self, app_designer: AppDesigner) -> None:
        await app_designer.aremove_design_object(self.id)
        logger.info(f"Deleted Design Object {self}")

    def save(self, workspace: Workspace) -> None:
        data_bytes = self.design_data
        if self.do_save_source:
            data_bytes = self.design_source
        design_path = self.design_path(workspace)
        design_path.path.parent.mkdir(parents=True, exist_ok=True)
        with open(design_path, "wb") as f:
            f.write(data_bytes)


class DesignType(IntEnum):
    ERROR = 0
    PAGE = 1
    RESOURCE = 2
    ACTION = 3
    SHARED_CODE = 4
    DOCUMENTATION = 5
    SCHEDULED_ACTION = 6
    WIDGET = 7

    @property
    def is_java_type(self) -> bool:
        return self in self.java_types()

    @classmethod
    def dirs(cls) -> list[str]:
        return [dt.name for dt in cls if dt > 0]

    def source_template(self, name: str) -> bytes:
        ret = (_ACTION_TEMPLATE % name) if self.is_java_type else ""
        if self == DesignType.SHARED_CODE:
            ret = _SHARED_CODE_TEMPLATE % name
        return ret.encode()

    @classmethod
    def from_name(cls, name: str) -> DesignType:
        for member in cls:
            if member.name.lower() == name.lower() and member != cls.ERROR:
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

    def content_type(self) -> str | None:
        if self.is_java_type:
            return _DEFAULT_JAVA_TYPE
        elif self == DesignType.PAGE:
            return "text/html"
        return None


class InvalidDesignPathError(Exception):
    pass


class DesignPath:
    """
    Represents a path to a Design Object. Expects format:
    /path/to/workspace/server/group/app_dir/design_dir/.../obj
    otherwise a InvalidDesignPathError is raised
    """

    def __init__(
        self, workspace: Workspace, path: Path, *, must_exist: bool = False
    ) -> None:
        try:
            rel_path = path.relative_to(workspace.path)
            server_dir, group_dir, app_dir, design_dir, _rem = str(rel_path).split(
                os.path.sep, maxsplit=4
            )
            app_dir_path = workspace.path / server_dir / group_dir / app_dir
            self.app = PuakmaApplication.from_dir(app_dir_path)
            if must_exist and not path.exists():
                raise ValueError(f"Design Object '{path}' does not exist")
        except ValueError as e:
            raise InvalidDesignPathError(f"Invalid path to Design Object '{path}': {e}")

        self.workspace = workspace
        self.path = path
        self.app_dir_path = app_dir_path
        self.design_dir = design_dir
        self.fname = path.name
        self.design_name, self.ext = os.path.splitext(self.fname)
        self.server_path = f"{self.app.group}/{self.app.name}.pma/{self.design_name}"

    def __str__(self) -> str:
        return str(self.path)

    def __fspath__(self) -> str:
        return str(self.path)

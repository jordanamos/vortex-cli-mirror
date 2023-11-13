from __future__ import annotations

import logging

import tabulate

from vortex.models import DatabaseConnection
from vortex.models import PuakmaServer
from vortex.workspace import Workspace

logger = logging.getLogger("vortex")


def db(
    workspace: Workspace,
    server: PuakmaServer,
    conn_id: int,
    sql: str | None,
    update: bool = False,
    limit_n_results: int = 5,
    schema_table: str | None = None,
    list_tables: bool = False,
) -> int:
    if schema_table is not None:
        sql = f"""\
            SELECT attributename AS name
                , type
                , typesize AS type_size
                , CASE
                    WHEN allownull = '1'
                    THEN 'Y'
                    ELSE 'N'
                END AS nullable
            FROM attribute a
            INNER JOIN pmatable t
            ON t.tableid = a.tableid
            WHERE dbconnectionid = {conn_id}
                AND lower(tablename) = '{schema_table}'
            ORDER BY attributename
        """
        update = False
        conn_id = server.puakma_db_conn_id
    elif sql is not None:
        sql = sql + f" LIMIT {limit_n_results}"
        # If we're modifying a database, lets check that its locally
        # cloned to ensure intent
        if update and not _check_connection_is_cloned(workspace, conn_id):
            logger.error(f"No cloned applications with DB Connection '{conn_id}'")
            return 1
    elif list_tables:
        sql = f"""\
            SELECT tablename
                , description
            FROM pmatable a
            WHERE dbconnectionid = {conn_id}
            ORDER BY tablename
        """
        update = False
        conn_id = server.puakma_db_conn_id

    if sql is not None:
        _output_result(server, conn_id, sql, update)
    return 0


def _check_connection_is_cloned(workspace: Workspace, conn_id: int) -> bool:
    """Returns True if the given conn_id exists in a locally cloned Application."""
    conns: list[DatabaseConnection] = []
    for app in workspace.listapps():
        if app.db_connections:
            conns.extend(app.db_connections)
    return any(conn.id == conn_id for conn in conns)


def _output_result(server: PuakmaServer, conn_id: int, sql: str, update: bool) -> None:
    with server:
        result = tuple(server.database_designer.execute_query(conn_id, sql, update))
        if result:
            print(tabulate.tabulate(result, headers="keys", maxcolwidths=50))
        else:
            logger.info("Query returned nil results.")

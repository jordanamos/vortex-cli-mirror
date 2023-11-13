from __future__ import annotations

import logging

import tabulate

from vortex import util
from vortex.models import PuakmaApplication
from vortex.models import PuakmaServer
from vortex.workspace import Workspace

logger = logging.getLogger("vortex")


def list_(
    workspace: Workspace,
    server: PuakmaServer,
    *,
    group_filter: list[str],
    name_filter: list[str],
    template_filter: list[str],
    show_ids_only: bool = False,
    show_inherited: bool = False,
    show_inactive: bool = False,
    show_local_only: bool = False,
    show_connections: bool = False,
    open_urls: bool = False,
    open_dev_urls: bool = False,
    show_all: bool = False,
    strict_search: bool = False,
) -> int:
    if show_local_only or show_connections:
        apps = _filter_apps(
            workspace.listapps(),
            name_filter,
            group_filter,
            template_filter,
            strict_search,
        )
    else:
        with server as s:
            apps = s.fetch_all_apps(
                name_filter,
                group_filter,
                template_filter,
                strict_search,
                show_inherited or show_all,
                show_inactive or show_all,
            )

    if show_connections:
        _render_db_connections(apps)
        return 0
    # Handle apps
    elif show_ids_only:
        for app in apps:
            print(app.id)
    elif open_urls or open_dev_urls:
        util.open_app_urls(*apps, open_dev_url=open_dev_urls)
    else:
        util.render_apps(apps, show_inherited=show_inherited or show_all)
    return 0


def _render_db_connections(apps: list[PuakmaApplication]) -> None:
    row_headers = ["Application", "ID", "Name"]

    row_data = []
    for app in sorted(apps, key=lambda x: (x.group.casefold(), x.name.casefold())):
        if app.db_connections:
            for conn in app.db_connections:
                row = (str(app), conn.id, conn.name)
                row_data.append(row)
    print(tabulate.tabulate(row_data, headers=row_headers))


def _filter_apps(
    apps: list[PuakmaApplication],
    name_filter: list[str] | None = None,
    group_filter: list[str] | None = None,
    template_filter: list[str] | None = None,
    strict_search: bool = False,
) -> list[PuakmaApplication]:
    def _match_attr(
        app: PuakmaApplication, attr: str, values: list[str] | None
    ) -> bool:
        return hasattr(app, attr) and (
            values is None
            or any(
                not strict_search
                and val.lower() in str(getattr(app, attr)).lower()
                or (strict_search and val == getattr(app, attr))
                for val in values
            )
        )

    filtered_apps = []
    for app in apps:
        name_match = _match_attr(app, "name", name_filter)
        template_match = _match_attr(app, "template_name", template_filter)
        group_match = _match_attr(app, "group", group_filter)
        if name_match and group_match and template_match:
            filtered_apps.append(app)
    return filtered_apps

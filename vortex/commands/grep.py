from __future__ import annotations

import functools
import re

from vortex.colour import Colour
from vortex.models import DesignObject
from vortex.models import DesignType
from vortex.models import PuakmaServer
from vortex.workspace import Workspace


def grep(
    workspace: Workspace,
    server: PuakmaServer,
    pattern: str,
    *,
    app_ids: list[int] | None = None,
    design_types: list[DesignType] | None = None,
    output_apps: bool = False,
    output_paths: bool = False,
    include_resources: bool = False,
) -> int:
    if design_types is None:
        design_types = [
            t
            for t in DesignType
            if t != DesignType.ERROR and (t != DesignType.RESOURCE or include_resources)
        ]

    if app_ids:
        apps = [workspace.lookup_app(server, id) for id in app_ids]
    else:
        apps = workspace.listapps(server)

    objs = [
        obj
        for app in apps
        for obj in app.design_objects
        if (not obj.is_jar_library)
        and (not design_types or obj.design_type in design_types)
    ]

    regex = re.compile(pattern.encode())
    matches: list[tuple[re.Match[bytes], DesignObject]] = []

    for obj in sorted(objs, key=lambda obj: obj.name):
        bytes_to_search = obj.design_source if obj.do_save_source else obj.design_data
        match = re.search(regex, bytes_to_search)
        if match:
            matches.append((match, obj))

    if output_apps:
        matched_apps = {obj.app for _, obj in matches}
        for app in matched_apps:
            print(app)
    else:
        _output_match_fn = functools.partial(
            _output, workspace, output_path=output_paths
        )
        for match, obj in matches:
            _output_match_fn(match, obj)
    return 0


def _output(
    workspace: Workspace,
    match: re.Match[bytes],
    obj: DesignObject,
    *,
    output_path: bool,
) -> None:
    try:
        text = match.string.decode()
    except UnicodeDecodeError:
        # Found a binary resource or jar library etc., skip
        return
    line_indx = text.count("\n", 0, match.start())
    line_no = line_indx + 1
    if output_path:
        print(f"{obj.design_path(workspace)}:{line_no}")
    else:
        matched_text = match.group().decode()
        line = text.splitlines()[line_indx].strip()
        new_text = Colour.colour(matched_text, Colour.RED, replace_in=line)
        print(f"{Colour.colour(obj.file_name, Colour.BOLD)}:{line_no} {new_text}")

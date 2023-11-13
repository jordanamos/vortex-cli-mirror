from __future__ import annotations

import functools
from argparse import _MutuallyExclusiveGroup
from argparse import _SubParsersAction
from argparse import ArgumentParser
from argparse import ArgumentTypeError
from pathlib import Path

from vortex.models import DesignType

NON_SERVER_COMMANDS = ("code", "clean", "config", "docs")


def _check_int_in_range(val: str, min: int = 0, max: int | None = 50) -> int:
    new_val = int(val)
    if new_val < min or (max is not None and new_val > max):
        raise ArgumentTypeError(f"%s is not between {min} and {max}. " % val)
    return new_val


def _add_server_option(parser: ArgumentParser) -> None:
    parser.add_argument(
        "--server",
        "-s",
        metavar="NAME",
        help="The name of the server definition in the config file to use",
    )


def _add_design_type_option(
    parser: ArgumentParser | _MutuallyExclusiveGroup,
    nargs: str | None = "*",
    required: bool = False,
) -> None:
    parser.add_argument(
        "--type",
        "-t",
        nargs=nargs,
        required=required,
        dest="design_type",
        type=DesignType.from_name,
        metavar="DESIGN_TYPE",
        help=(
            f"Choices: {[t.name.lower() for t in DesignType if t != DesignType.ERROR]}"
        ),
    )


def add_code_parser(
    command_parser: _SubParsersAction[ArgumentParser],
) -> ArgumentParser:
    code_parser = command_parser.add_parser(
        "code",
        help="Open the workspace in Visual Studio Code",
        add_help=False,
    )
    code_parser.add_argument("--help", "-h", action="store_true")
    return code_parser


def add_list_parser(command_parser: _SubParsersAction[ArgumentParser]) -> None:
    list_parser = command_parser.add_parser(
        "list",
        aliases=("ls",),
        help=(
            "List Puakma Applications on the server or cloned locally."
            "(ls is an alias for 'vortex list --local')"
        ),
    )
    list_parser.add_argument(
        "--group",
        "-g",
        nargs="*",
        help="Enter application 'group' to filter the results",
    )
    list_parser.add_argument(
        "--name",
        "-n",
        nargs="*",
        help="Enter application 'name' to filter the results",
    )
    list_parser.add_argument(
        "--template",
        "-t",
        nargs="*",
        help="Enter application 'template' to filter the results",
    )
    list_parser.add_argument(
        "--strict",
        help="Strict search when using filters",
        action="store_true",
    )
    list_parser.add_argument(
        "--local",
        action="store_true",
        dest="show_local_only",
        help="List locally cloned applications instead",
    )
    list_parser.add_argument(
        "--show-inherited",
        help="Also display inherited applications",
        action="store_true",
    )
    list_parser.add_argument(
        "--show-inactive",
        help="Also display inactive applications",
        action="store_true",
    )
    list_parser.add_argument(
        "--all",
        "-a",
        help="Show all applications",
        action="store_true",
    )
    list_parser.add_argument(
        "--ids-only",
        "-x",
        help="Show application ID's only",
        dest="show_ids_only",
        action="store_true",
    )
    list_parser.add_argument(
        "--open-urls",
        "-o",
        help="Open each application URL in a web browser",
        action="store_true",
    )
    list_parser.add_argument(
        "--open-dev-urls",
        "-d",
        help="Open each application webdesign URL in a web browser",
        action="store_true",
    )
    list_parser.add_argument(
        "--show-connections",
        help="List the Database Connections of locally cloned apps",
        action="store_true",
    )
    _add_server_option(list_parser)


def add_clone_parser(
    command_parser: _SubParsersAction[ArgumentParser],
) -> ArgumentParser:
    clone_parser = command_parser.add_parser(
        "clone",
        help="Clone Puakma Applications and their design objects into the workspace",
    )
    clone_parser.add_argument(
        "app_ids",
        nargs="*",
        metavar="APP_ID",
        help="The ID(s) of the Puakma Application(s) to clone",
        type=int,
    )
    clone_parser.add_argument(
        "--reclone",
        help="Reclone locally cloned applictions",
        action="store_true",
    )
    clone_parser.add_argument(
        "--get-resources",
        "-r",
        help="Also clone application resources",
        action="store_true",
    )
    clone_parser.add_argument(
        "--open-urls",
        "-o",
        help="Open the application and webdesign URLs after cloning",
        action="store_true",
    )
    clone_parser.add_argument(
        "--export",
        nargs="?",
        metavar="PMX_PATH",
        dest="export_path",
        const="",
        help=(
            "Export applications in the .pmx format to a destination "
            "folder. Default is 'exports' in the workspace."
        ),
        type=Path,
    )
    _add_server_option(clone_parser)
    return clone_parser


def add_watch_parser(command_parser: _SubParsersAction[ArgumentParser]) -> None:
    watch_parser = command_parser.add_parser(
        "watch",
        help=(
            "Watch the workspace for changes to Design Objects "
            "and upload them to the server"
        ),
    )
    _add_server_option(watch_parser)


def add_clean_parser(command_parser: _SubParsersAction[ArgumentParser]) -> None:
    command_parser.add_parser(
        "clean",
        help="Delete the cloned Puakma Application directories in the workspace",
    )


def add_config_parser(command_parser: _SubParsersAction[ArgumentParser]) -> None:
    config_parser = command_parser.add_parser(
        "config", help="View and manage configuration"
    )
    config_mutex = config_parser.add_mutually_exclusive_group(required=True)
    config_mutex.add_argument(
        "--sample",
        dest="print_sample",
        action="store_true",
        help="Print a sample 'vortex-server-config.ini' file to the console",
    )
    config_mutex.add_argument(
        "--update-vscode-settings",
        action="store_true",
        help="Update the vortex.code-workspace file. Creating it if doesn't exist",
    )
    config_mutex.add_argument(
        "--reset-vscode-settings",
        action="store_true",
        help="Recreate the vortex.code-workspace file",
    )
    config_mutex.add_argument(
        "--output-config-path", action="store_true", help="Output the config file path"
    )
    config_mutex.add_argument(
        "--output-workspace-path", action="store_true", help="Output the workspace path"
    )
    config_mutex.add_argument(
        "--output-server-config",
        action="store_true",
        help="Output the current server definition in the config file.",
    )
    _add_server_option(config_parser)


def add_log_parser(command_parser: _SubParsersAction[ArgumentParser]) -> None:
    log_parser = command_parser.add_parser(
        "log", help="View the last items in the server log"
    )
    log_parser.add_argument(
        "--limit",
        "-n",
        type=_check_int_in_range,
        help="The number of logs to return (max 50). Default is %(default)s",
        default=10,
    )
    log_parser.add_argument("--source", help="Filter the logs returned by their source")
    log_parser.add_argument(
        "--message", "-m", help="Filter the logs returned by their message"
    )
    log_type_mutex = log_parser.add_mutually_exclusive_group()
    log_type_mutex.add_argument("--errors-only", action="store_true")
    log_type_mutex.add_argument("--debug-only", action="store_true")
    log_type_mutex.add_argument("--info-only", action="store_true")
    log_parser.add_argument("--keep-alive", "-k", action="store_true")

    _positive_int = functools.partial(_check_int_in_range, min=1)
    log_parser.add_argument(
        "--delay",
        "-d",
        type=_positive_int,
        help=(
            "Used only with --keep-alive. "
            "The number of seconds betwen requests for new logs. Default is %(default)s"
        ),
        default=5,
        metavar="SECONDS",
    )
    _add_server_option(log_parser)


def add_find_parser(command_parser: _SubParsersAction[ArgumentParser]) -> None:
    find_parser = command_parser.add_parser(
        "find",
        help="Find Design Objects of cloned applications by name",
        usage="%(prog)s [options] name",
    )
    find_parser.add_argument("name", help="The name of Design Objects to find")
    find_parser.add_argument("--app-id", type=int, nargs="*", dest="app_ids")
    find_parser.add_argument("--strict", "-z", action="store_true")
    find_parser.add_argument(
        "--ids-only",
        "-x",
        help="Display Object ID's in the output only",
        dest="show_ids_only",
        action="store_true",
    )
    find_parser.add_argument(
        "--show-params",
        help="Also display the Design Object parameters",
        action="store_true",
    )
    _add_design_type_option(find_parser)
    _add_server_option(find_parser)


def add_grep_parser(command_parser: _SubParsersAction[ArgumentParser]) -> None:
    grep_parser = command_parser.add_parser(
        "grep",
        help=(
            "Search the contents of cloned Design Objects using a Regular Expression."
        ),
        usage="%(prog)s [options] pattern",
    )
    grep_parser.add_argument("pattern", help="The Regular Expression pattern to match")
    grep_parser.add_argument("--app-id", type=int, nargs="*", dest="app_ids")

    grep_output_mutex = grep_parser.add_mutually_exclusive_group()
    grep_output_mutex.add_argument("--output-paths", action="store_true")
    grep_output_mutex.add_argument("--output-apps", action="store_true")

    grep_design_type_mutex = grep_parser.add_mutually_exclusive_group()
    grep_design_type_mutex.add_argument(
        "--include-resources",
        "-r",
        help="Set this flag to also search resources",
        action="store_true",
    )
    _add_design_type_option(grep_design_type_mutex)
    _add_server_option(grep_parser)


def add_new_parser(
    command_parser: _SubParsersAction[ArgumentParser],
) -> ArgumentParser:
    def _pmx_type(val: str) -> Path:
        path = Path(val).resolve()
        if path.suffix != ".pmx" or not path.is_file():
            raise ArgumentTypeError(f"Invalid '.pmx' file {path}")
        return path

    new_parser = command_parser.add_parser(
        "new",
        help="Create new Design Objects, Applications or Keywords",
    )
    _add_server_option(new_parser)

    sub_parser = new_parser.add_subparsers(dest="subcommand")

    object_parser = sub_parser.add_parser("object", help="Create a new Design Object")
    object_parser.add_argument("--app-id", type=int, required=True)
    object_parser.add_argument("--name", "-n", required=True)
    _add_design_type_option(object_parser, nargs=None, required=True)

    obj_optional_group = object_parser.add_argument_group("Optional Arguments")
    obj_optional_group.add_argument("--comment")
    obj_optional_group.add_argument("--inherit-from")
    obj_optional_group.add_argument("--open-action")
    obj_optional_group.add_argument("--save-action")
    obj_optional_group.add_argument("--parent-page")
    obj_optional_group.add_argument(
        "--content-type",
        help=(
            "The content/mime Type. "
            "Required when creating a 'resource' or 'documentation'"
        ),
    )

    app_parser = sub_parser.add_parser("app", help="Create a new Puakama Application")
    app_parser.add_argument("--name", "-n", help="The application name", required=True)
    app_parser.add_argument(
        "--group", "-g", help="The application group", required=True
    )
    app_optional_group = app_parser.add_argument_group("Optional Arguments")
    app_optional_group.add_argument("--description")
    app_optional_group.add_argument("--inherit-from")
    app_optional_group.add_argument("--template")
    app_optional_group.add_argument(
        "--import",
        metavar="PMX_PATH",
        type=_pmx_type,
        dest="import_path",
        help="Create the application from the given .pmx path",
    )

    keyword_parser = sub_parser.add_parser("keyword", help="Create a new Keyword")
    keyword_parser.add_argument("--app-id", type=int, required=True)
    keyword_parser.add_argument("--name", "-n", help="The keyword name", required=True)
    keyword_parser.add_argument("--values", nargs="*", required=True)

    return new_parser


def add_copy_parser(command_parser: _SubParsersAction[ArgumentParser]) -> None:
    copy_parser = command_parser.add_parser(
        "copy", help="Copy a Design Object from one application to another"
    )
    copy_parser.add_argument("ids", nargs="+", metavar="DESIGN_ID", type=int)
    copy_parser.add_argument(
        "--app-id",
        type=int,
        required=True,
        help="The App ID to copy the object to",
    )

    copy_parser.add_argument("--copy-params", action="store_true")
    _add_server_option(copy_parser)


def add_delete_parser(command_parser: _SubParsersAction[ArgumentParser]) -> None:
    delete_parser = command_parser.add_parser(
        "delete", help="Delete Design Object(s) by ID"
    )
    delete_parser.add_argument("obj_ids", nargs="+", type=int, metavar="DESIGN_ID")
    _add_server_option(delete_parser)


def add_db_parser(command_parser: _SubParsersAction[ArgumentParser]) -> None:
    db_parser = command_parser.add_parser(
        "db", help="Interact with Database Connections"
    )
    db_parser.add_argument(
        "connection_id",
        metavar="CONNECTION_ID",
        type=int,
        help="The Database Connection ID",
    )
    db_mutex = db_parser.add_mutually_exclusive_group(required=True)
    db_mutex.add_argument("--sql", help="Execute a given SQL query")
    db_mutex.add_argument(
        "--schema",
        metavar="TABLE_NAME",
        help="View the schema of a table",
    )
    db_mutex.add_argument(
        "--list",
        "-l",
        action="store_true",
        help="List the tables in the Database",
    )
    db_parser.add_argument(
        "--update",
        "-u",
        action="store_true",
        help="Set this flag when running querys for altering/updating the database",
    )
    db_parser.add_argument(
        "--limit",
        "-n",
        metavar="N",
        type=_check_int_in_range,
        help=(
            "The number of results to be returned when using --sql between 1 and 50. "
            "This flag adds the 'LIMIT' clause of the given SQL query. "
            "Default is %(default)s."
        ),
        default=5,
    )


def add_docs_parser(command_parser: _SubParsersAction[ArgumentParser]) -> None:
    command_parser.add_parser("docs", help="Open the Torndao Server Blackbook")


def add_execute_parser(command_parser: _SubParsersAction[ArgumentParser]) -> None:
    execute_parser = command_parser.add_parser(
        "execute",
        aliases=("exec",),
        help="Execute a command on the server. Execute '?' for more info.",
    )
    execute_parser_mutex = execute_parser.add_mutually_exclusive_group(required=True)
    execute_parser_mutex.add_argument(
        "cmd", help="The command to execute", metavar="CMD", nargs="?", default=""
    )
    execute_parser_mutex.add_argument(
        "--refresh-design",
        type=int,
        help="Refresh an application's design",
        dest="refresh_app_id",
        metavar="APP_ID",
    )
    _add_server_option(execute_parser)

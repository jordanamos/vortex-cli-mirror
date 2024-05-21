from __future__ import annotations

import argparse
import contextlib
import logging
from collections.abc import Generator
from collections.abc import Sequence

from httpx import HTTPStatusError

from vortex import cli
from vortex import constants as C
from vortex import util
from vortex.colour import Colour
from vortex.commands.clean import clean
from vortex.commands.clone import clone
from vortex.commands.code import code
from vortex.commands.config import config
from vortex.commands.copy import copy_
from vortex.commands.db import db
from vortex.commands.delete import delete
from vortex.commands.docs import docs
from vortex.commands.execute import execute
from vortex.commands.find import find
from vortex.commands.grep import grep
from vortex.commands.list import list_
from vortex.commands.log import log
from vortex.commands.new import new
from vortex.commands.watch import watch
from vortex.logging import logging_handler
from vortex.logging import LoggingHandler
from vortex.workspace import Workspace
from vortex.workspace import WorkspaceError


logger = logging.getLogger("vortex")


@contextlib.contextmanager
def error_handler() -> Generator[None, None, None]:
    try:
        yield
    except (WorkspaceError, HTTPStatusError) as e:
        logger.error(e)
        raise SystemExit(1)
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as e:
        msg = f"An unexpected error occured. {e}".rstrip()
        logger.critical(msg)
        LoggingHandler.log_to_file_and_exit(e, 3)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vortex", description="Vortex command line tool"
    )
    parser.add_argument(
        "--version", "-V", action="version", version=f"vortex-cli {C.VERSION}"
    )
    parser.add_argument(
        "--workspace",
        "-w",
        metavar="DIR",
        help="Override the Workspace directory path",
    )
    parser.add_argument(
        "--no-colour",
        action="store_true",
        help="Suppress coloured output",
    )
    parser.add_argument(
        "--verbose",
        "--debug",
        "-v",
        help="Show debug messages",
        action="store_true",
    )
    parser.add_argument(
        "--init",
        action="store_true",
        help="Initialise the workspace and config files, if they don't already exist",
    )

    command_parser = parser.add_subparsers(dest="command")
    cli.add_list_parser(command_parser)
    cli.add_clean_parser(command_parser)
    cli.add_config_parser(command_parser)
    cli.add_copy_parser(command_parser)
    cli.add_delete_parser(command_parser)
    cli.add_find_parser(command_parser)
    cli.add_grep_parser(command_parser)
    cli.add_log_parser(command_parser)
    cli.add_watch_parser(command_parser)
    cli.add_db_parser(command_parser)
    cli.add_docs_parser(command_parser)
    cli.add_execute_parser(command_parser)
    clone_parser = cli.add_clone_parser(command_parser)
    code_parser = cli.add_code_parser(command_parser)
    new_parser = cli.add_new_parser(command_parser)

    args, remaining_args = parser.parse_known_args(argv)
    # Call this for initial Validation
    if args.command != "code":
        parser.parse_args(argv)

    cli.validate_args(args, new_parser, clone_parser)

    if args.no_colour:
        Colour.disable()

    with logging_handler(args.verbose), error_handler():
        workspace_path = getattr(args, "workspace", None)
        server_name = getattr(args, "server", None)

        workspace = Workspace(workspace_path, args.init)
        server = workspace.read_server_from_config(server_name)

        LoggingHandler.workspace = workspace

        # No command
        if not args.command:
            print(workspace.path)
            return 0

        if args.command == "clean":
            return clean(workspace)
        elif args.command == "code":
            if args.help:
                code_parser.print_help()
                util.print_row_break()
                remaining_args.insert(0, "--help")
            return code(workspace, remaining_args)
        elif args.command == "config":
            return config(
                workspace,
                server,
                print_sample=args.print_sample,
                update_vscode_settings=args.update_vscode_settings,
                reset_vscode_settings=args.reset_vscode_settings,
                output_config_path=args.output_config_path,
                output_workspace_path=args.output_workspace_path,
                output_server_config=args.output_server_config,
                list_servers=args.list_servers,
                set=args.set,
            )
        elif args.command == "docs":
            return docs()
        elif args.command in ("list", "ls"):
            local_only = args.show_local_only or args.command == "ls"
            return list_(
                workspace,
                server,
                group_filter=args.group,
                name_filter=args.name,
                template_filter=args.template,
                show_ids_only=args.show_ids_only,
                show_inherited=args.show_inherited,
                show_inactive=args.show_inactive,
                show_local_only=local_only,
                open_urls=args.open_urls,
                open_dev_urls=args.open_dev_urls,
                show_connections=args.show_connections,
                show_all=args.all,
                strict_search=args.strict,
            )
        elif args.command == "clone":
            return clone(
                workspace,
                server,
                args.app_ids,
                get_resources=args.get_resources,
                open_urls=args.open_urls,
                reclone=args.reclone,
                export_path=args.export_path,
                timeout=args.timeout,
            )
        elif args.command == "watch":
            return watch(workspace, server)
        elif args.command == "log":
            return log(
                server,
                args.limit,
                args.source,
                args.message,
                args.errors_only,
                args.info_only,
                args.debug_only,
                args.keep_alive,
                args.delay,
            )
        elif args.command == "find":
            return find(
                workspace,
                server,
                args.name,
                app_ids=args.app_ids,
                design_types=args.design_type,
                show_params=args.show_params,
                show_ids_only=args.show_ids_only,
                strict_search=args.strict,
            )
        elif args.command == "grep":
            return grep(
                workspace,
                server,
                args.pattern,
                app_ids=args.app_ids,
                design_types=args.design_type,
                output_paths=args.output_paths,
                output_apps=args.output_apps,
                include_resources=args.include_resources,
            )
        elif args.command == "new":
            return new(workspace, server, args)
        elif args.command == "delete":
            return delete(workspace, server, args.obj_ids)
        elif args.command == "copy":
            return copy_(
                workspace,
                server,
                args.ids,
                to_app_id=args.app_id,
                copy_params=args.copy_params,
            )
        elif args.command == "db":
            return db(
                workspace,
                server,
                args.connection_id,
                args.sql,
                update=args.update,
                limit_n_results=args.limit,
                schema_table=args.schema,
                list_tables=args.list,
                truncate_cols=args.truncate_cols,
            )
        elif args.command in ("execute", "ex"):
            return execute(
                workspace,
                server,
                args.cmd,
                args.refresh_app_id,
                args.run_action_path,
                args.schedule,
            )
        else:
            raise NotImplementedError(f"Command '{args.command}' is not implemented.")


if __name__ == "__main__":
    raise SystemExit(main())

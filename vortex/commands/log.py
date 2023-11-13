from __future__ import annotations

import functools
import time
from datetime import datetime

import tabulate

from vortex import util
from vortex.colour import Colour
from vortex.models import LogItem
from vortex.models import PuakmaServer
from vortex.spinner import Spinner

_LOG_TYPE_COLOUR_MAP = {
    "D": Colour.YELLOW,
    "I": Colour.TURQUOISE,
    "E": Colour.RED,
}


def log(
    server: PuakmaServer,
    limit: int,
    source_filter: str | None,
    messsage_filter: str | None,
    errors_only: bool,
    info_only: bool,
    debug_only: bool,
    keep_alive: bool = False,
    delay: int = 3,
) -> int:
    with server as s:
        get_logs = functools.partial(
            s.get_last_log_items,
            limit,
            source_filter,
            messsage_filter,
            errors_only,
            info_only,
            debug_only,
        )
        logs = get_logs()

        row_headers = ("Time", "Source", "Message")
        col_widths = [None, 30, 65]
        row_data = _format_log_rows(logs)
        print(tabulate.tabulate(row_data, headers=row_headers, maxcolwidths=col_widths))
        if keep_alive:
            with Spinner("Monitoring Server Log, ^C to stop"):
                while True:
                    last_log_item = max(logs, key=lambda x: x.id)
                    new_logs = get_logs(last_log_item.id)
                    if new_logs:
                        row_data = _format_log_rows(new_logs)
                        print(
                            tabulate.tabulate(
                                row_data, tablefmt="plain", maxcolwidths=col_widths
                            )
                        )
                        logs = new_logs
                    time.sleep(delay)
    return 0


def _format_log_rows(logs: list[LogItem]) -> list[tuple[str, str, str]]:
    rows = []
    for log in sorted(logs, key=lambda x: x.date):
        log_colour = _LOG_TYPE_COLOUR_MAP[log.type]
        row = (
            Colour.colour(datetime.strftime(log.date, "%H:%M:%S"), log_colour),
            util.shorten_or_pad_text(log.item_source, min_len=30),
            log.msg,
        )
        rows.append(row)
    return rows

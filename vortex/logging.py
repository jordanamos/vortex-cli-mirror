from __future__ import annotations

import contextlib
import functools
import logging
import sys
import traceback
from collections.abc import Generator
from typing import IO
from typing import NoReturn

from vortex.colour import Colour
from vortex.soap import SOAPResponseParseError
from vortex.workspace import Workspace

logger = logging.getLogger("vortex")


class _LoggingFormatter(logging.Formatter):
    LOG_LEVEL_COLORS = {
        logging.DEBUG: "",
        logging.INFO: Colour.GREEN,
        logging.WARNING: Colour.YELLOW,
        logging.ERROR: Colour.RED,
        logging.CRITICAL: Colour.RED,
    }

    def __init__(self) -> None:
        self.fmt = "%(asctime)s [%(levelname)s] %(message)s"
        self.datefmt = "%H:%M:%S"
        super().__init__(self.fmt, self.datefmt)

    def format(self, record: logging.LogRecord) -> str:
        level = record.levelname
        msg = super().format(record)
        new_msg = Colour.colour(
            f"[{level}]", self.LOG_LEVEL_COLORS[record.levelno], replace_in=msg
        )
        return new_msg


class LoggingHandler(logging.Handler):
    workspace: Workspace | None = None

    def __init__(self) -> None:
        super().__init__()
        self.setFormatter(_LoggingFormatter())

    @staticmethod
    def _output_msg(
        msg: str | None = None,
        stream: IO[bytes] = sys.stdout.buffer,
    ) -> None:
        if msg is not None:
            stream.write(msg.encode())
        stream.write(b"\n")
        stream.flush()

    @staticmethod
    def _get_soap_err_msg(exc: SOAPResponseParseError) -> str:
        msg = ""
        for ele in exc.response.iter():
            msg += f"{ele.tag} ({ele.attrib}):\n"
            text = ele.text.strip() if ele.text else None
            if text:
                lines = [f"\t{line}\n" for line in text.splitlines()]
                for line in lines:
                    msg += line
        return msg

    @classmethod
    def log_to_file_and_exit(cls, exc: Exception, ret_code: int) -> NoReturn:
        with contextlib.ExitStack() as ctx:
            if cls.workspace is not None:
                cls.workspace.logs_dir.mkdir(exist_ok=True)
                log_file_path = cls.workspace.logs_dir / "vortex.log"
                cls._output_msg(f"Check the log at {log_file_path}")
                log: IO[bytes] = ctx.enter_context(open(log_file_path, "wb"))
            else:
                cls._output_msg("Failed to write to log file. No Workspace set.")
                log = sys.stdout.buffer

            error_msg = f"{type(exc).__name__}:\n{exc}"
            soap_err_msg = ""
            if isinstance(exc, SOAPResponseParseError):
                soap_err_msg = cls._get_soap_err_msg(exc)
            formatted_err = traceback.format_exc()

            _log_line = functools.partial(cls._output_msg, stream=log)

            _log_line()
            _log_line("### error information")
            _log_line()
            _log_line("```")
            _log_line(f"{error_msg}")
            _log_line("```")
            _log_line()
            if soap_err_msg:
                _log_line("### soap response")
                _log_line()
                _log_line("```")
                _log_line(soap_err_msg)
                _log_line("```")
                _log_line()
            _log_line("### traceback")
            _log_line()
            _log_line("```")
            _log_line(formatted_err.rstrip())
            _log_line("```")
        raise SystemExit(ret_code)

    def emit(self, record: logging.LogRecord) -> None:
        msg = self.format(record)
        self._output_msg(msg)


@contextlib.contextmanager
def logging_handler(verbose: bool) -> Generator[None, None, None]:
    handler = LoggingHandler()
    httpx_logger = logging.getLogger("httpx")
    watchfiles_logger = logging.getLogger("watchfiles")

    logger.addHandler(handler)
    httpx_logger.addHandler(handler)
    watchfiles_logger.addHandler(handler)

    if verbose:
        logger.setLevel(logging.DEBUG)
        httpx_logger.setLevel(logging.DEBUG)
        watchfiles_logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.INFO)
        httpx_logger.setLevel(logging.ERROR)
        watchfiles_logger.setLevel(logging.ERROR)
    try:
        yield
    finally:
        logger.removeHandler(handler)
        httpx_logger.removeHandler(handler)
        watchfiles_logger.removeHandler(handler)

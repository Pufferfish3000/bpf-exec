import argparse
import sys
from c2.view import C2View
from typing import Optional, NoReturn, Any


def get_command_args() -> argparse.Namespace:
    """Return parsed c2 command line arguments

    Returns:
        argparse.Namespace: C2 command line arguments
    """
    parser = argparse.ArgumentParser(description="BPF Exec C2", prog="python3 -m c2")
    parser.add_argument(
        "-p", "--log-file", default="C2.log", help="Path to the log file"
    )
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode")

    return parser.parse_args()


class BadArgument(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class C2Parser(argparse.ArgumentParser):

    def _print_message(self, message: str, file: Optional[Any] = None) -> None:
        """prints out a message using the c2 color format without writing to a logfile

        Args:
            message (str): message to display.
            file (Optional[SupportsWrite[str]], optional): File to write to. Defaults to sys.stderr.
        """
        if message:
            info_msg = "[*] "
            colored_info_msg = C2View.colored_text(info_msg, "E55381")
            for line in message.split("\n"):
                new_msg = C2View.colored_text(line, "FFFFFF")
                if file is None:
                    file = sys.stderr
                file.write(f"{colored_info_msg}{new_msg}\n")

    def exit(self, status: int = 0, message: Optional[str] = None) -> NoReturn:
        """Overwritten exit method as to not exit the program on bad argument or --help

        Args:
            status (int, optional): Unused. Defaults to 0.
            message (Optional[str], optional): Exit message. Defaults to None.

        Raises:
            BadArgument: Exception, user used bad argument or --help
        """
        if message:
            self._print_message(message, sys.stderr)
        raise BadArgument(message or "Bad argument provided")

    def error(self, message: str) -> NoReturn:
        """Overwritten error message as to provide usage prints that align with the c2 theme

        Args:
            message (str): error message

        Raises:
            BadArgument: Exception, user used bad argument or --help
        """
        error_msg = "[-] "
        colored_error_msg = C2View.colored_text(error_msg, "FF3A20")
        self.print_usage(sys.stderr)
        for line in message.split("\n"):
            message = C2View.colored_text(line, "FFFFFF")
            sys.stderr.write(f"{colored_error_msg}{message}\n")
        raise BadArgument(message or "Bad argument provided")

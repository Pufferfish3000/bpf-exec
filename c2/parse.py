import argparse


def get_command_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BPF Exec C2")
    parser.add_argument(
        "-p", "--log-file", default="C2.log", help="Path to the log file"
    )
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode")

    return parser.parse_args()

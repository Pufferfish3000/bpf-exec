# BERKLEY PACKET FILTER REMOTE EXECUTABLE

BPF EXEC is a proof-of-concept tool designed to explore techniques in network protocol obfuscation and covert communication channels. It is not intended for use in any production environment, offensive security engagement without explicit authorization, or for malicious purposes.

## Overview

BPF EXEC is composed of two components:

Agent (C)
- Listens on a raw BPF socket for specially crafted packets.
- Matches and extracts payloads from traffic disguised as TLS or DTLS.
- Executes payloads using /bin/bash.

C2 (Python)
- Configures new agents with specific parameters.
- Sends tasks to agents, including shell commands and shutdown instructions.
- Obfuscates payloads to resemble TLS/DTLS traffic (note: no real encryption is used).

Features
- Passive remote shell execution via network sniffing.
- Obfuscation of control traffic to appear as legitimate protocol data.
- Minimal and lightweight C-based agent.
- No active connection initiated by the agent.

Note: The current implementation of the C2 only supports one specific TLS and one specific DTLS packet format. For more effective obfuscation, especially in environments with packet inspection, you would need to expand the supported protocols and introduce variability in packet construction. Repeated use of identical-looking packets may raise suspicion in monitored environments

## Build

### Agent

```bash
make build
```

### C2

Agent must be built to run the C2

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

```

## Usage

### Running the C2

Scapy must be installed

```bash
usage: python3 -m c2 [-h] [-p LOG_FILE] [-d]

BPF Exec C2

options:
  -h, --help            show this help message and exit
  -p LOG_FILE, --log-file LOG_FILE
                        Path to the log file
  -d, --debug           Enable debug mode
```

LOG_FILE records all commands and output that is run

### C2 Commands

#### configure

configure stamps an agent with provided options for execution, and writes the configured agent to `output`/`name`.agent

```bash
usage: configure [-h] {tcp,udp} [-h] --name NAME [--output OUTPUT] [--seq SEQ] [--dport DPORT]

Configure the BPF Remote Shell Executable Agent.

positional arguments:
  {tcp,udp}
    tcp            Configure agent for TCP
    udp            Configure agent for UDP

options:
  -h, --help       show this help message and exit
  --name NAME      Name of the agent
  --output OUTPUT  Output file for the agent
  --dport DPORT    Destination port that the agent will be listening for udp only
  --seq SEQ        Sequence number that the agent will be listening for tcp only
```

### shell

```bash
usage: shell [-h] {tcp,udp} [-h] [--sip SIP] --dip DIP [--sport SPORT] [--dport DPORT] [--seq SEQ] command

positional arguments:
   {tcp,udp}
    tcp            Send a shell command over TCP
    udp            Send a shell command over UDP
    command        Shell command to send to the agent

options:
  -h, --help       show this help message and exit
  --sip SIP        Source IP address for the Raw packet (default: 8.8.8.8)
  --dip DIP        Destination IP address for the Raw packet
  --sport SPORT    Source port for the Raw packet (default: 4444)
  --dport DPORT    Destination port for the Raw packet (default: 4444)
  --seq SEQ        Sequence number for TCP Raw packet (default: 5445) tcp only
```
#### help

Displays all available commands
 
#### exit

Exits the command loop


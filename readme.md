# Root bridge hijack attack

This is a command-line tool developed in Python that uses the `curses` library for its graphical interface. The tool can send Bridge Protocol Data Unit (BPDU) packets to hijack the root bridge in a network, and it can enable packet forwarding using a bridge.

## Prerequisites

- Linux Operating System
- Root Privileges
- Python version 3.5+ (Script was written in Python 3.11.3)
- 1 Network interface to Hijack root bridge
- 2 Network interfaces to Enable packet forwarding (Man-in-the-Middle)

## Installation

Clone the repository and install the required Python libraries as follows:

```bash
git clone https://github.com/Jellyyyyyyy/STP_MiTM.git
cd project
pip install -r requirements.txt
```

## Usage

To use this tool, run the script with root privileges:

```bash
sudo python3 main.py
```

The tool provides a terminal-based GUI where you can choose from various options. Follow the instructions on the screen to perform the desired actions.

## Features

- **Root Bridge Hijacking:** This tool can hijack the root bridge in a network by sending BPDU packets.<br>NOTE: Will Not work if BPDU guard is enabled on the switch's interface
- **Packet Forwarding:** Enable or disable packet forwarding using a bridge. This feature requires at least two network interfaces.
- **Trunk Interface Establishment:** Establish a trunk interface by sending a crafted Dynamic Trunking Protocol (DTP) packet.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
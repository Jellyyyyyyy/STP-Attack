# STP Root Bridge Hijack 

![Python Version](https://img.shields.io/badge/python-3.x-blue?style=for-the-badge&logo=python)
![OS](https://img.shields.io/badge/OS-GNU%2FLinux-red?style=for-the-badge&logo=linux)

An interactive Python program capable of sending Bridge Protocol Data Unit (BPDU) packets to hijack the root bridge in a network and enable packet forwarding using a bridge.
The script uses the `curses`, `scapy` and `netifaces` libraries to establish the compromised switch as the root switch, enabling the user to gain access to the packets in the network for various attacks (see [Features](#features)).

### Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Features](#features)

## Prerequisites

1. **OS**
    * Linux Operating System
    * Root Privileges

2. **Python modules**
    * Python version 3.5+ (Script was written in Python 3.11.3)
    * Scapy Module: Can be downloaded using `pip install scapy`. For Scapy [installation](https://github.com/secdev/scapy/blob/master/README.md) and [documentation](https://scapy.readthedocs.io/en/latest/introduction.html) to get started on Scapy
    * Netifaces Module: Can be downloaded using `pip install netifaces`.

3. **Others**
    * 1 network interface to hijack root bridge
    * 2 network interfaces to enable packet forwarding (Man-in-The-Middle)

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
(do we wanna add a gif to show how the gui is being used or nah?????????)

## Features

- **Root Bridge Hijacking:** This tool can hijack the root bridge in a network by sending BPDU packets.<br>NOTE: Will Not work if BPDU guard is enabled on the switch's interface
- **Packet Forwarding:** Enable or disable packet forwarding using a bridge. This feature requires at least two network interfaces.
- **Trunk Interface Establishment:** Establish a trunk interface by sending a crafted Dynamic Trunking Protocol (DTP) packet.
- **DNS Spoofing:** WE SPOOF DA DNS HEHEHEEEE

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

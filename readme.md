# Network Hijack & Forwarding Tool

This is a command-line tool developed in Python that uses the `curses` library for its graphical interface. The tool can send Bridge Protocol Data Unit (BPDU) packets to hijack the root bridge in a network, and it can enable packet forwarding using a bridge. However, the packet forwarding feature is only available on PCs with at least two network interfaces.

## Prerequisites

This tool is designed to run on Linux machines and requires root privileges. Also, for a man-in-the-middle attack scenario with packet forwarding, two network interfaces are needed. However, the Spanning Tree Protocol (STP) attack can be conducted with just one network interface.

## Installation

Clone the repository and install the required Python libraries as follows:

```bash
git clone https://github.com/username/project.git
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

- **Root Bridge Hijacking:** This tool can hijack the root bridge in a network by sending BPDU packets.
- **Packet Forwarding:** Enable or disable packet forwarding using a bridge. This feature requires at least two network interfaces.
- **Trunk Interface Establishment:** Establish a trunk interface by sending a crafted Dynamic Trunking Protocol (DTP) packet.

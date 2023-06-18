# STP ATTACK

![Python Version](https://img.shields.io/badge/python-3.6+-blue?style=for-the-badge&logo=python)
![OS](https://img.shields.io/badge/OS-GNU%2FLinux-red?style=for-the-badge&logo=linux)
[![Liscense](https://img.shields.io/badge/LICENSE-MIT-green?style=for-the-badge)](LICENSE)

An interactive Python program capable of sending Bridge Protocol Data Unit (BPDU) packets to hijack the root bridge in a network and enable packet forwarding using a bridge.
The script uses the `curses`, `scapy` and `netifaces` libraries to establish the compromised switch as the root switch, enabling the user to gain access to the packets in the network for various attacks (see [Features](#features)).

## Disclaimer

This tool is developed for educational and ethical use within authorized environments only. 
Please make sure to read the full [DISCLAIMER](DISCLAIMER) before using this tool.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Features](#features)
- [Troubleshooting](#troubleshooting)

## Prerequisites

1. **OS**
    * Linux Operating System, preferably Kali Linux
    * Root Privileges

2. **Python modules**
    * Python version 3.6+ (Script was written in Python 3.11.3)
    * Python libraries required are `scapy` and `netifaces` which can be installed manually or with `requirements.txt`

3. **Others**
    * One network interface to hijack root bridge
    * Two network interfaces to enable packet forwarding (Man-in-The-Middle)

## Installation

Clone the repository and install the required Python libraries as follows:

```bash
git clone https://github.com/Jellyyyyyyy/STP-Attack.git
cd STP-Attack
pip install -r requirements.txt
```

## Usage

To use this tool, run the script with root privileges:

```bash
sudo python3 main.py
```

The tool provides a terminal-based GUI where you can choose from various options. Follow the instructions on the screen to perform the desired actions.

## Configuration

This tool offers some configurations, primarily administered through two key files: `configs/config` and `configs/attacks`. Each file houses its own set of customizable options:

### configs/config

Here is a glimpse of what `configs/config` file looks like:

```json
{
    "version": "2.0",
    "verbose": false,
    "stop_time": 3,
    "skip_choosing_interfaces": false
}
```

The fields are defined as follows:

- `version`: Specifies the current version of the attack tool.
- `verbose`: If set to `true`, it enables debug information. Please be aware that this feature is under development, and you may encounter issues with string formatting in the console.
- `stop_time`: Defines the time delay (in seconds) when halting an attack, except for packet forwarding.
- `skip_choosing_interfaces`: If the system detects only two interfaces, setting this to `true` bypasses the interface selection process.

### configs/attacks

Each attack is structured following the basic template below:

```json
"attack_name": {
    "enabled": true,
    "start": "Start Root Bridge Hijack",
    "stop": "Stop Hijack",
    "settings": {}
}
```

Each element of an attack configuration comprises:

- `attack_name`: Indicates the unique name of the attack.
- `enabled`: Determines whether the attack appears in the attack tool menu.
- `start`: Represents the label for initiating the attack in the attack tool menu.
- `stop`: Represents the label for terminating the attack in the attack tool menu.
- `settings`: This is a placeholder for custom settings for each specific attack. 


## Features

- **Root Bridge Hijacking**
  - Manipulates the root bridge by transmitting superior BPDU packets.
  - Requires no active BPDU guard on the switch's interface.
  - Interval between sending out BPDU packets can be configured in the [attacks configuraiton file](configs/attacks).
  - Path cost for interface 1 and 2 can also be configured in [attacks configuraiton file](configs/attacks).

- **Packet Forwarding**
  - Forms a bridge between two network interfaces, forwarding packets.
  - Allows for a Man-In-The-Middle (MITM) attack.
  - Requires two network interfaces.

- **DNS Spoofing**
  - Relies on being the root bridge to intercept DNS queries.
  - Intercepts and modifies DNS responses to lead to the IP that the attacker specifies.
  - Uses IP tables to block legitimate DNS responses. Can be disabled in the [attacks configuraiton file](configs/attacks).

Please use responsibly and comply with all relevant laws and regulations.

## Troubleshooting

1. **Hijacking root bridge**
   - Check that the STP packets are being sent out using wireshark.
   - Check that the incoming STP packets have the MAC address of what you set in the [config file](configs/config).
   - Try restarting the program if no for the above.
2. **Packet forwarding**
   - Check that before packet forwarding is enabled, the bridge (`hijack_stp_br`) is not created yet. 
   - Check that after packet forwarding is enabled, the bridge is created.
   - If it is created before packet forwarding is enabled, delete it with the `brctl` module, `brctl delbr hijack_stp_br`.
   - If it is not created after packet forwarding is enabled, restart the program
3. **DNS Hijacking**
   - Check that there is a web server hosting a website at the IP you specify.
   - Use Wireshark to see if the DNS packets are being resolved to the specified IP. If no, try restarting the program

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

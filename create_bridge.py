import socket
import fcntl
import struct
import glob
import os
import time
from threading import Thread

# Flags are from linux/sockios.h which is used in fcntl.ioctl
CREATE_BR = 0x89a0  # Create bridge; SIOCBRADDBR
DEL_BR = 0x89a1  # Delete bridge; SIOCBRDELBR
ADD_IF_TO_BR = 0x89a2  # Add interface to bridge; SIOCBRADDIF
RM_IF_FROM_BR = 0x89a3  # Remove interface from bridge; SIOCBRDELIF
SET_IF_FLAGS = 0x8914  # Set interface flags; SIOCSIFFLAGS
GET_IF_INDEX = 0x8933  # Get interface index; SIOCGIFINDEX

IF_DOWN = 0x0  # Interface down
IF_UP = 0x1  # Interface up

config = {
    "VERBOSE": False
}


def vprint(msg):
    """print if verbose is set"""
    if config["VERBOSE"]:
        print(msg)


def create_bridge(bridge_name):
    """Creates bridge"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    fcntl.ioctl(sock, CREATE_BR, bridge_name)
    sock.close()


def delete_bridge(bridge_name):
    """Deletes bridge"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    fcntl.ioctl(sock, DEL_BR, bridge_name)
    sock.close()


def get_iface_index(interface_name):
    """Returns interface index"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    request = struct.pack("16sI", interface_name.encode("utf-8"), 0)
    response = fcntl.ioctl(sock, GET_IF_INDEX, request)
    interface_index = struct.unpack("16sI", response)[1]
    sock.close()
    return interface_index


def add_iface_to_br(bridge_name, interface_name):
    """Add interface to bridge"""
    interface_index = get_iface_index(interface_name)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    data = struct.pack("16si", bridge_name.encode("utf-8"), interface_index)
    fcntl.ioctl(sock, ADD_IF_TO_BR, data)
    sock.close()


def del_iface_from_br(bridge_name, interface_name):
    """Remove interface from bridge"""
    interface_index = get_iface_index(interface_name)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    data = struct.pack("16si", bridge_name.encode("utf-8"), interface_index)
    fcntl.ioctl(sock, RM_IF_FROM_BR, data)
    sock.close()


def bring_iface_up(interface_name):
    """Brings specified interface up"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    ifr = struct.pack("16sh", interface_name.encode("utf-8"), IF_UP)
    fcntl.ioctl(sock, SET_IF_FLAGS, ifr)
    sock.close()


def bring_iface_down(interface_name):
    """Brings specified interface down"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    ifr = struct.pack("16sh", interface_name.encode("utf-8"), IF_DOWN)
    fcntl.ioctl(sock, SET_IF_FLAGS, ifr)
    sock.close()


def delete_br_ifaces(bridge_name):
    """Deletes all interfaces from bridge"""
    interfaces = get_ifaces_in_br(bridge_name)
    for interface in interfaces:
        del_iface_from_br(bridge_name, interface)
        vprint(f"Removed interface {interface} from bridge {bridge_name}")


def bridge_exists(bridge_name):
    """Checks if bridge exists or not"""
    return os.path.isdir(f"/sys/class/net/{bridge_name}/bridge")


def get_ifaces_in_br(bridge_name):
    """Get interfaces attached to bridge"""
    return [os.path.basename(p) for p in glob.glob(f"/sys/class/net/{bridge_name}/brif/*")]


def verify_bridge(bridge_name, interfaces, verification_attempt=0):
    """Verify that the bridge has both interfaces"""
    if verification_attempt > 5:
        vprint(f"Could not verify bridge")
        return False

    if bridge_exists(bridge_name):
        bridge_interfaces = get_ifaces_in_br(bridge_name)
        missing_interfaces = [interface for interface in interfaces if interface not in bridge_interfaces]

        if missing_interfaces:
            vprint(f"The following interfaces are missing from bridge {bridge_name}: {missing_interfaces}")
            vprint(f"Deleting bridge {bridge_name} to fix its interfaces")
            delete_br_ifaces(bridge_name)
            delete_bridge(bridge_name)
            vprint(f"Creating bridge {bridge_name} with interfaces {interfaces}")
            create_bridge(bridge_name)
            for interface in interfaces:
                add_iface_to_br(bridge_name, interface)
            if verify_bridge(bridge_name, interfaces, verification_attempt + 1):
                return True
            return False
        else:
            vprint(f"Bridge {bridge_name} exists and has the correct interfaces")
            return True
    else:
        vprint(f"Bridge {bridge_name}, does not exist")
        return False


def monitor(bridge_name, interfaces):
    """Monitors the bridge to check if there are missing interfaces, fixes them if anything is wrong"""
    while True:
        if not bridge_exists(bridge_name):
            vprint(f"Bridge {bridge_name} does not exist, terminating monitoring thread...")
            return
        else:
            missing_interfaces = [i for i in interfaces if i not in get_ifaces_in_br(bridge_name)]
            if missing_interfaces:
                vprint(f"The following interfaces are missing from bridge {bridge_name}, adding them: \
                        {missing_interfaces}")
                bring_iface_down(bridge_name)
                for interface in missing_interfaces:
                    add_iface_to_br(bridge_name, interface)
                bring_iface_up(bridge_name)
        time.sleep(1)


def start(bridge_name, interfaces: list, verbose=False):
    """Creates a bridge and adds the interfaces specified to them"""
    config["VERBOSE"] = verbose
    vprint(f"Creating bridge {bridge_name} with interfaces {', '.join(interfaces)}")
    create_bridge(bridge_name)
    vprint(f"Created bridge {bridge_name}")
    for interface in interfaces:
        add_iface_to_br(bridge_name, interface)
        vprint(f"Added interface {interface} to bridge {bridge_name}")

    if verify_bridge(bridge_name, interfaces):
        bring_iface_up(bridge_name)
    else:
        vprint(f"Could not verify bridge, aborting...")
        stop(bridge_name)

    monitor_thread = Thread(target=monitor, args=(bridge_name, interfaces,))
    monitor_thread.daemon = True
    monitor_thread.start()


def stop(bridge_name, verbose=False):
    """Removes interfaces from the bridge and deletes bridge"""
    config["VERBOSE"] = verbose
    if bridge_exists(bridge_name):
        vprint(f"Found bridge {bridge_name}, deleting...")
        delete_br_ifaces(bridge_name)
        bring_iface_down(bridge_name)
        delete_bridge(bridge_name)
        vprint(f"Bridge {bridge_name} deleted.")
    else:
        vprint(f"Bridge {bridge_name} does not exist.")

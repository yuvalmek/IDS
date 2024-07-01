from scapy.all import *


def send_icmp_packet():
    ip = IP(dst="127.0.0.1")  # Replace with the target IP address
    icmp = ICMP()
    packet = ip / icmp
    packet.show()
    send(packet, verbose=True)
    print("Packet sent")


send_icmp_packet()

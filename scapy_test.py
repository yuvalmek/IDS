from scapy.all import sniff


def packet_callback(pkt):
    print(f"Packet received: {pkt.summary()}")


print("start")
sniff(prn=packet_callback, filter="icmp", store=0)

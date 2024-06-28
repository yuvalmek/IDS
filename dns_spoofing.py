from scapy.all import *

legitimate_dns = {
    "example.com": "93.184.216.34"
}


def detect_dns_spoof(pkt):
    if DNS in pkt and pkt[DNS].qr == 1:  # DNS response
        query_name = pkt[DNSQR].qname.decode().rstrip('.')
        if query_name in legitimate_dns:
            legitimate_ip = legitimate_dns[query_name]
            response_ip = pkt[DNSRR].rdata
            if response_ip != legitimate_ip:
                print(f"DNS Spoofing detected: {query_name} resolved to {response_ip}, but should be {legitimate_ip}")


loopback_interface = '\\Device\\NPF_Loopback'
sniff(prn=detect_dns_spoof, filter="udp port 53", store=0, iface=loopback_interface)

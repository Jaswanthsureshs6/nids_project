from scapy.all import sniff, IP
from datetime import datetime

def packet_callback(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        protocol = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, "OTHER")
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] {protocol} {src} -> {dst} | Size: {len(packet)} bytes")

def start_sniffing(interface=None, count=100):
    print("[*] Sniffing started... CTRL+C to stop.")
    packets = sniff(iface=interface, prn=packet_callback, store=True, count=count)
    print("[*] Sniffing finished.")
    return packets

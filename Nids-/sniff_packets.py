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

def start_sniffing(interface=None):
    print("Sniffing started... CTRL+C to stop.")
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    start_sniffing("en0")  # on Mac, 'en0' is usually the Wi-Fi interface


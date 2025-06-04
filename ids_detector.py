from scapy.all import *
import logging

logging.basicConfig(filename="ids_alerts.log", level=logging.INFO, format='%(asctime)s - %(message)s')

ip_traffic = {}
PORT_SCAN_THRESHOLD = 10
arp_cache = {}

def log_alert(message):
    logging.info(message)
    print(f"ALERT: {message}")
def packet_callback(packet):
    global ip_traffic, arp_cache
    
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            src_port = packet.sport
            if ip_src not in ip_traffic:
                ip_traffic[ip_src] = set()
            ip_traffic[ip_src].add(src_port)
            
            if len(ip_traffic[ip_src]) > PORT_SCAN_THRESHOLD:
                log_alert(f"Port scan detected from IP: {ip_src}, attempted {len(ip_traffic[ip_src])} ports.")
        
        if packet.haslayer(ARP):
            arp_src_ip = packet[ARP].psrc
            arp_src_mac = packet[ARP].hwsrc
            if arp_src_ip in arp_cache:
                if arp_cache[arp_src_ip] != arp_src_mac:
                    log_alert(f"Possible ARP spoofing detected: IP {arp_src_ip} has different MAC addresses {arp_cache[arp_src_ip]} and {arp_src_mac}.")
            else:
                arp_cache[arp_src_ip] = arp_src_mac

def start_sniffing():
    print("IDS is running... Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=0, filter="ip or arp", timeout=60)

if __name__ == "__main__":
    start_sniffing()

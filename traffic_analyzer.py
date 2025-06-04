from scapy.all import TCP

def analyze_traffic(packets):
    suspicious_packets = []

    for pkt in packets:
        if pkt.haslayer(TCP):
            # Check if TCP SYN flag is set and ACK is not set (common in scans)
            if pkt[TCP].flags == 'S':
                suspicious_packets.append(pkt)

    return suspicious_packets

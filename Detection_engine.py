def detect_intrusion(suspicious_packets):
    if suspicious_packets:
        return {
            "type": "TCP SYN Scan Detected",
            "count": len(suspicious_packets),
            "details": [(pkt[0][1].src, pkt[0][1].dst) for pkt in suspicious_packets]
        }
    else:
        return None

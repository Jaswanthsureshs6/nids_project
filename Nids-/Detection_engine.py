from scapy.all import sniff, IP
import time
from datetime import datetime
from collections import defaultdict

log_file = "detection_log.txt"
protocol_count = defaultdict(int)
suspicious_activity = []

MAX_PACKET_SIZE = 1500
TRAFFIC_THRESHOLD = 1000
TIME_WINDOW = 60

traffic_data = defaultdict(list)

def detect_anomalies():
    current_time = time.time()

    for ip, times in traffic_data.items():
        traffic_data[ip] = [t for t in times if current_time - t < TIME_WINDOW]

        if len(traffic_data[ip]) > TRAFFIC_THRESHOLD:
            suspicious_activity.append(f"High traffic from {ip} in the last {TIME_WINDOW} seconds")

def packet_callback(packet):
    global suspicious_activity
    
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        size = len(packet)
        
        traffic_data[src_ip].append(time.time())
        
        detect_anomalies()

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {src_ip} -> {dst_ip} | Proto: {proto} | Size: {size} bytes"
        with open(log_file, "a") as log:
            log.write(line + "\n")
        
        print(line)

def alert_on_suspicious_activity():
    if suspicious_activity:
        print("\n🚨 Suspicious Activity Detected! 🚨")
        for activity in suspicious_activity:
            print(activity)

def start(interface="en0"):
    print("🔍 Monitoring for suspicious traffic... Press CTRL+C to stop.\n")
    try:
        sniff(iface=interface, prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print("\n\n📊 Detection Summary:")
        alert_on_suspicious_activity()

if __name__ == "__main__":
    start("en0")

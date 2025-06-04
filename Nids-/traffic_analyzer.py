from scapy.all import sniff, IP
from datetime import datetime
from collections import defaultdict

log_path = "traffic_log.txt"
proto_stats = defaultdict(int)
total_traffic = {"packets": 0, "bytes": 0}

def handle_packet(packet):
    if not packet.haslayer(IP):
        return

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    proto_num = ip_layer.proto

    proto_map = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }
    proto_name = proto_map.get(proto_num, f"Proto-{proto_num}")

    pkt_size = len(packet)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    line = f"[{timestamp}] {proto_name} {src_ip} -> {dst_ip} | Size: {pkt_size} bytes"
    print(line)

    with open(log_path, "a") as log:
        log.write(line + "\n")

    proto_stats[proto_name] += 1
    total_traffic["packets"] += 1
    total_traffic["bytes"] += pkt_size

def start(interface="en0"):
    print(" Monitoring traffic... Press CTRL+C to stop.\n")
    try:
        sniff(iface=interface, prn=handle_packet, store=False)
    except KeyboardInterrupt:
        print("\n\n📊 Summary:")
        print(f"Total packets: {total_traffic['packets']}")
        print(f"Total data transferred: {total_traffic['bytes']} bytes")
        print("Protocol breakdown:")
        for proto, count in proto_stats.items():
            print(f" - {proto}: {count}")

if __name__ == "__main__":
    start("en0")
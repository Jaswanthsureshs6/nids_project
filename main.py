from sniff_packets import start_sniffing
from traffic_analyzer import analyze_traffic
from Detection_engine import detect_intrusion
from alert_generator import generate_alert

def main():
    print("[*] Starting NIDS...")

    packets = start_sniffing("en0")  # or None for all interfaces
    print(f"[*] Captured {len(packets)} packets.")

    analysis_result = analyze_traffic(packets)
    print("[*] Traffic analysis complete.")

    intrusion_result = detect_intrusion(analysis_result)
    print("[*] Intrusion detection complete.")

    if intrusion_result:
        generate_alert(intrusion_result)
        print("[!] Alert generated.")
    else:
        print("[✓] No intrusion detected.")

if __name__ == "__main__":
    main()

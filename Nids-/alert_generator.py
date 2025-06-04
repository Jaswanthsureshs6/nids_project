import time
import os

LOG_FILE = 'detection_log.txt'

def monitor_alerts():
    print("[*] Monitoring alerts... Press CTRL+C to stop.")
    if not os.path.exists(LOG_FILE):
        print(f"[!] {LOG_FILE} not found.")
        return

    with open(LOG_FILE, 'r') as file:
        file.seek(0, os.SEEK_END)  # Go to end of file

        while True:
            line = file.readline()
            if line:
                print(f"[ALERT] {line.strip()}")
            else:
                time.sleep(1)

if __name__ == "__main__":
    try:
        monitor_alerts()
    except KeyboardInterrupt:
        print("\n[!] Stopped monitoring.")
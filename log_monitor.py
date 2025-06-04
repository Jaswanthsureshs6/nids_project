import os
import shutil
from datetime import datetime

def rotate_log(file_path):
    if os.path.exists(file_path):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        new_name = f"{file_path}_{timestamp}.bak"
        shutil.move(file_path, new_name)
        print(f"[+] Archived log: {new_name}")
    else:
        print("[!] Log file not found.")

if __name__ == "__main__":
    rotate_log("detection_log.txt")
    rotate_log("traffic_log.txt")

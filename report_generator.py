def generate_report(log_file):
    try:
        with open(log_file, 'r') as file:
            lines = file.readlines()

        total = len(lines)
        print(f"\n📊 Summary Report for {log_file}")
        print("-" * 40)
        print(f"Total Alerts: {total}")
        print(f"Sample Alerts:\n")
        for line in lines[-5:]:  # Show last 5 alerts
            print(line.strip())
    except FileNotFoundError:
        print(f"[!] {log_file} not found.")

if __name__ == "__main__":
    generate_report("detection_log.txt")

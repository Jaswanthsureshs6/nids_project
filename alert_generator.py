def generate_alert(intrusion_details):
    alert_message = f"[ALERT] Intrusion Detected: {intrusion_details['type']}\n"
    alert_message += f"Packet Count: {intrusion_details['count']}\n"
    alert_message += "Suspicious Connections:\n"

    for src, dst in intrusion_details["details"]:
        alert_message += f"  {src} -> {dst}\n"

    print(alert_message)

    # Optionally, log to a file
    with open("ids_alerts.log", "a") as log_file:
        log_file.write(alert_message + "\n")


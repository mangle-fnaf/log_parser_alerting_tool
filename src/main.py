import datetime
import os
import requests

# webhook URL for Discord notifications
WEBHOOK_URL = "https://discord.com/api/webhooks/1556771799901933689/thUPtfEgVmfQG4ihHtHYrYNuuSBJ4K0BsU7PPFe5Xo7MIC42NceL2fRXvzETzVnfDu7k"

LOG_FILE_PATH = "logs/sample.log"

# Codes that will be flagged, number of attempts, checks for attacks occuring within 10 seconds of each other
FAILED_STATUS_CODES = {"401", "403"}
MAX_FAILED_ATTEMPTS = 3
TIME_WINDOW_SECONDS = 10  # e.g. 10 seconds


def parse_log_line(line):
    # splits and strips the text line
    parts = line.strip().split()
    # safety check = if there is less than 5 segments, the system skips it.
    if len(parts) < 5:
        return None

    timestamp_str = f"{parts[0]} {parts[1]}"
    ip = parts[2]
    method = parts[3]
    path = parts[4]
    status = parts[5] if len(parts) > 5 else "200"

    # Converts raw timestring stamp into python datetime. If it does not match the format, it returns value none.
    try:
        timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

    # organises pieces and sends it back to caller.
    return {
        "timestamp": timestamp,
        "ip": ip,
        "method": method,
        "path": path,
        "status": status,
    }


def load_logs(path):
    events = []
    with open(path, "r") as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                events.append(parsed)
    return events


# detects brute force attacks
def detect_bruteforce(events):
    suspicious = []

    # sort by time
    events = sorted(events, key=lambda e: e["timestamp"])

    # Tracks when an IP was last flagged to prevent duplicate overlapping alerts
    last_flagged_until = {}

    # If the log entry was a successful request, it immediately skips it.
    for i, event in enumerate(events):
        if event["status"] not in FAILED_STATUS_CODES:
            continue

        # window starts (10 seconds). Registers initial failed attempt.
        window_start = event["timestamp"]
        ip = event["ip"]

        # Skip this event if we've already generated an alert covering this time period for this IP
        if ip in last_flagged_until and window_start <= last_flagged_until[ip]:
            continue

        failed_count = 1
        last_failed_time = window_start

        # it looks through logs present after. If it belongs to the same IP, ignore it.
        for j in range(i + 1, len(events)):
            next_event = events[j]
            if next_event["ip"] != ip:
                continue

            # if window more than 10 seconds, it breaks the inner loop.
            delta = (next_event["timestamp"] - window_start).total_seconds()
            if delta > TIME_WINDOW_SECONDS:
                break

            if next_event["status"] in FAILED_STATUS_CODES:
                failed_count += 1
                last_failed_time = next_event["timestamp"]

        # if the counter is more than 3, it creates an alert dictionary.
        if failed_count >= MAX_FAILED_ATTEMPTS:
            suspicious.append(
                {
                    "ip": ip,
                    "start_time": window_start,
                    "failed_count": failed_count,
                }
            )
            # Lock out this IP from causing duplicate alerts until this specific window cluster finishes
            last_flagged_until[ip] = last_failed_time

    return suspicious


# alerting function
def send_alert(alerts):
    if not WEBHOOK_URL:
        print("Webhook URL not set. Skipping alert.")
        return

    message_lines = ["**Suspicious activity detected:**"]
    for alert in alerts:
        message_lines.append(
            f"- IP `{alert['ip']}` had **{alert['failed_count']}** failed attempts "
            f"starting at `{alert['start_time']}`"
        )

    payload = {"content": "\n".join(message_lines)}

    try:
        response = requests.post(WEBHOOK_URL, json=payload)
        # FIXED: Added the collection check to resolve the syntax error
        if response.status_code in range(200, 300):
            print("Alert sent to Discord.")
        else:
            print(
                f"Discord rejected the alert. Status Code: {response.status_code}, Response: {response.text}"
            )
    except Exception as e:
        print(f"Failed to send alert: {e}")


# outputs results
def main():
    events = load_logs(LOG_FILE_PATH)
    bruteforce_alerts = detect_bruteforce(events)

    if bruteforce_alerts:
        print("[!] Suspicious activity detected:")
        for alert in bruteforce_alerts:
            print(
                f"- IP {alert['ip']} had {alert['failed_count']} failed attempts "
                f"starting at {alert['start_time']}"
            )

        send_alert(bruteforce_alerts)

    else:
        print("No suspicious activity detected.")


if __name__ == "__main__":
    main()

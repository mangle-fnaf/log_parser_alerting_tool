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
                    "type": "bruteforce",  # Added type key
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

    message_lines = ["Suspicious activity detected:"]

    for alert in alerts:
        # Brute-force alerts
        if alert.get("type") == "bruteforce":  # Changed to safely use type check
            message_lines.append(
                f"- IP {alert['ip']} had {alert['failed_count']} failed attempts "
                f"starting at {alert['start_time']}"
            )

        # Admin access, after-hours, high-volume, etc.
        elif "reason" in alert:
            message_lines.append(
                f"- IP {alert['ip']} at {alert['time']}: {alert['reason']}"
            )

        # Fallback (just in case)
        else:
            message_lines.append(f"- IP {alert['ip']} triggered an alert.")

    payload = {"content": "\n".join(message_lines)}

    try:
        requests.post(WEBHOOK_URL, json=payload)
        print("Alert sent to Discord.")
    except Exception as e:
        print(f"Failed to send alert: {e}")

#detects high volume of requests from a single IP within a short time frame
def detect_high_volume(events, threshold=10, window_seconds=5):
    suspicious = []

    # Sort by time
    events = sorted(events, key=lambda e: e["timestamp"])

    for i, event in enumerate(events):
        ip = event["ip"]
        start_time = event["timestamp"]
        count = 1

        for j in range(i + 1, len(events)):
            next_event = events[j]
            if next_event["ip"] != ip:
                continue

            delta = (next_event["timestamp"] - start_time).total_seconds()
            if delta > window_seconds:
                break

            count += 1

        if count >= threshold:
            suspicious.append({
                "type": "high_volume",  # Added type key
                "ip": ip,
                "time": start_time,
                "count": count,
                "reason": f"High request volume ({count} requests in {window_seconds}s)"
            })

    return suspicious

#detects activity outside of normal hours (midnight to 6 AM)
def detect_after_hours(events):
    suspicious = []

    for event in events:
        hour = event["timestamp"].hour
        if hour < 6:  # midnight to 6 AM
            suspicious.append({
                "type": "after_hours",  # Added type key
                "ip": event["ip"],
                "time": event["timestamp"],
                "reason": "Activity outside normal hours"
            })

    return suspicious

#Flags admin access attempts.
def detect_admin_access(events):
    suspicious = []

    for event in events:
        if event["path"] == "/admin":
            suspicious.append({
                "type": "admin_access",  # Added type key
                "ip": event["ip"],
                "time": event["timestamp"],
                "reason": "Accessed /admin page"
            })

    return suspicious

# outputs results
def main():
    events = load_logs(LOG_FILE_PATH)

    bruteforce_alerts = detect_bruteforce(events)
    admin_alerts = detect_admin_access(events)
    after_hours_alerts = detect_after_hours(events)
    volume_alerts = detect_high_volume(events)

    all_alerts = bruteforce_alerts + admin_alerts + after_hours_alerts + volume_alerts

    if all_alerts:
        print("[!] Suspicious activity detected:")
        for alert in all_alerts:
            if alert["type"] == "bruteforce":
                print(
                    f"- IP {alert['ip']} had {alert['failed_count']} failed attempts "
                    f"starting at {alert['start_time']}"
                )
            else:
                print(f"- IP {alert['ip']} at {alert['time']}: {alert['reason']}")

        send_alert(all_alerts)

    else:
        print("No suspicious activity detected.")


if __name__ == "__main__":
    main()

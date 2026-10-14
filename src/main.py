#imports python modules
import datetime #timestamps
import os #file paths
import requests #sending discord webhook alerts
import json #reading config

with open("src/config.json", "r") as cfg:
    CONFIG = json.load(cfg)

#rules as config files and stores them as variables for easy access. Adds easy flexibility
WEBHOOK_URL = CONFIG["webhook_url"]
LOG_FILE_PATH = CONFIG["log_file_path"]
FAILED_STATUS_CODES = set(CONFIG["failed_status_codes"])
MAX_FAILED_ATTEMPTS = CONFIG["max_failed_attempts"]
TIME_WINDOW_SECONDS = CONFIG["bruteforce_time_window"]
ALLOW_LIST = set(CONFIG["allow_list"])
SUSPICIOUS_USER_AGENTS = CONFIG["suspicious_user_agents"]
HIGH_VOLUME_THRESHOLD = CONFIG["high_volume_threshold"]
HIGH_VOLUME_WINDOW = CONFIG["high_volume_window"]
ENDPOINT_SCAN_THRESHOLD = CONFIG["endpoint_scan_threshold"]
ENDPOINT_SCAN_WINDOW = CONFIG["endpoint_scan_window"]
SEVERITY_OVERRIDES = CONFIG["severity"]
SEVERITY_COLOURS_CFG = CONFIG["severity_colours"]
RULES_ENABLED = CONFIG["rules"]

#Adds visual indicators for severity levels in the console output
SEVERITY_ICONS = {
    "high": "🔴",
    "medium": "🟠",
    "low": "🟢"
}

#Splits each log line into components, validates the format
#converts the tiestamp string to a python datetime object, returns a dictionary with the parsed data, or None if the line is invalid.
def parse_log_line(line):
    parts = line.strip().split()
    if len(parts) < 7:
        return None

    timestamp_str = f"{parts[0]} {parts[1]}"
    ip = parts[2]
    method = parts[3]
    path = parts[4]
    status = parts[5]
    user_agent = " ".join(parts[6:])

    try:
        timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

    return {
        "timestamp": timestamp,
        "ip": ip,
        "method": method,
        "path": path,
        "status": status,
        "user_agent": user_agent
    }

#reads the log file line by line, uses parse_log_line to parse each line, and collects valid events into a list. Returns the list of events.
def load_logs(path):
    events = []
    with open(path, "r") as f:
        for line in f:
            parsed = parse_log_line(line)
            if parsed:
                events.append(parsed)
    return events

#Detects brute force attacks by checking for multiple failed login attempts from the same IP within a specified time window. If the number of failed attempts exceeds the configured threshold, it flags the IP as suspicious and adds it to the list of alerts.
def detect_bruteforce(events):
    if not RULES_ENABLED["bruteforce"]:
        return []

    suspicious = []
    events = sorted(events, key=lambda e: e["timestamp"])
    last_flagged_until = {}

    for i, event in enumerate(events):
        if event["ip"] in ALLOW_LIST:
            continue

        if event["status"] not in FAILED_STATUS_CODES:
            continue

        window_start = event["timestamp"]
        ip = event["ip"]

        if ip in last_flagged_until and window_start <= last_flagged_until[ip]:
            continue

        failed_count = 1
        last_failed_time = window_start

        for j in range(i + 1, len(events)):
            next_event = events[j]
            if next_event["ip"] != ip:
                continue

            delta = (next_event["timestamp"] - window_start).total_seconds()
            if delta > TIME_WINDOW_SECONDS:
                break

            if next_event["status"] in FAILED_STATUS_CODES:
                failed_count += 1
                last_failed_time = next_event["timestamp"]

        if failed_count >= MAX_FAILED_ATTEMPTS:
            suspicious.append({
                "ip": ip,
                "time": window_start,
                "reason": f"{failed_count} failed login attempts in {TIME_WINDOW_SECONDS}s",
                "type": "bruteforce",
                "severity": SEVERITY_OVERRIDES["bruteforce"]
            })

    return suspicious

#detects after-hours activity between 00:00 and 06:00, flags any activity from IPs not in the allow list during this time as suspicious.
def detect_after_hours(events):
    if not RULES_ENABLED["after_hours"]:
        return []

    suspicious = []

    for event in events:
        if event["ip"] in ALLOW_LIST:
            continue

        hour = event["timestamp"].hour
        if hour < 6:
            suspicious.append({
                "ip": event["ip"],
                "time": event["timestamp"],
                "reason": "Activity outside normal hours",
                "type": "after_hours",
                "severity": SEVERITY_OVERRIDES["after_hours"]
            })

    return suspicious

#detects access to /admin endpoints, flags any access attempts to /admin paths from IPs not in the allow list as suspicious.
def detect_admin_access(events):
    if not RULES_ENABLED["admin_access"]:
        return []

    suspicious = []

    for event in events:
        if event["ip"] in ALLOW_LIST:
            continue

        if event["path"].startswith("/admin"):
            suspicious.append({
                "ip": event["ip"],
                "time": event["timestamp"],
                "reason": "Accessed /admin page",
                "type": "admin_access",
                "severity": SEVERITY_OVERRIDES["admin_access"]
            })

    return suspicious

#detects high volume requests from the same IP within a specified time window. If the number of requests exceeds the configured threshold, it flags the IP as suspicious and adds it to the list of alerts.
def detect_high_volume(events):
    if not RULES_ENABLED["high_volume"]:
        return []

    suspicious = []
    events = sorted(events, key=lambda e: e["timestamp"])

    for i, event in enumerate(events):
        if event["ip"] in ALLOW_LIST:
            continue

        ip = event["ip"]
        start_time = event["timestamp"]
        count = 1

        for j in range(i + 1, len(events)):
            next_event = events[j]
            if next_event["ip"] != ip:
                continue

            delta = (next_event["timestamp"] - start_time).total_seconds()
            if delta > HIGH_VOLUME_WINDOW:
                break

            count += 1

        if count >= HIGH_VOLUME_THRESHOLD:
            suspicious.append({
                "ip": ip,
                "time": start_time,
                "reason": f"{count} requests in {HIGH_VOLUME_WINDOW}s",
                "type": "high_volume",
                "severity": SEVERITY_OVERRIDES["high_volume"]
            })

    return suspicious

#detects endpoint scanning by checking for multiple unique paths accessed from the same IP within a specified time window. If the number of unique paths exceeds the configured threshold, it flags the IP as suspicious and adds it to the list of alerts.
def detect_endpoint_scanning(events):
    if not RULES_ENABLED["endpoint_scan"]:
        return []

    suspicious = []
    events = sorted(events, key=lambda e: e["timestamp"])

    for i, event in enumerate(events):
        if event["ip"] in ALLOW_LIST:
            continue

        ip = event["ip"]
        start_time = event["timestamp"]
        paths_seen = {event["path"]}

        for j in range(i + 1, len(events)):
            next_event = events[j]
            if next_event["ip"] != ip:
                continue

            delta = (next_event["timestamp"] - start_time).total_seconds()
            if delta > ENDPOINT_SCAN_WINDOW:
                break

            paths_seen.add(next_event["path"])

        if len(paths_seen) >= ENDPOINT_SCAN_THRESHOLD:
            suspicious.append({
                "ip": ip,
                "time": start_time,
                "reason": f"{len(paths_seen)} unique endpoints scanned",
                "type": "endpoint_scan",
                "severity": SEVERITY_OVERRIDES["endpoint_scan"]
            })

    return suspicious

#detects suspicious user agents by checking if the user agent string of each event contains any known suspicious patterns. If a match is found, it flags the IP as suspicious and adds it to the list of alerts.
def detect_suspicious_user_agents(events):
    if not RULES_ENABLED["suspicious_user_agent"]:
        return []

    suspicious = []

    for event in events:
        if event["ip"] in ALLOW_LIST:
            continue

        ua = event["user_agent"].lower()

        for bad in SUSPICIOUS_USER_AGENTS:
            if bad in ua:
                suspicious.append({
                    "ip": event["ip"],
                    "time": event["timestamp"],
                    "reason": f"Suspicious user-agent: '{event['user_agent']}'",
                    "type": "suspicious_user_agent",
                    "severity": SEVERITY_OVERRIDES["suspicious_user_agent"]
                })
                break

    return suspicious

#keeps only the strongest alert for each IP and type combination, based on the severity of the reason. This prevents multiple alerts for the same issue from cluttering the output.
def dedupe_alerts(alerts):
    strongest = {}

    for alert in alerts:
        key = (alert["ip"], alert["type"])

        if key not in strongest:
            strongest[key] = alert
            continue

        existing = strongest[key]

        if alert["type"] in ("bruteforce", "high_volume", "endpoint_scan"):
            if int(alert["reason"].split()[0]) > int(existing["reason"].split()[0]):
                strongest[key] = alert

        else:
            continue

    return list(strongest.values())

#builds a discord embed and sends it using the webhook URL. It includes the highest severity alert in the embed color and lists all alerts with their details.
def send_alert(alerts):
    if not WEBHOOK_URL:
        print("Webhook URL not set. Skipping alert.")
        return

    severity_icons = {
        "high": "🔴",
        "medium": "🟠",
        "low": "🟢"
    }

    SEVERITY_COLOURS = {
        "high": 0xFF0000,
        "medium": 0xFFA500,
        "low": 0x00FF00
    }

    highest = max(alerts, key=lambda a: {"high": 3, "medium": 2, "low": 1}[a["severity"]])
    colour = SEVERITY_COLOURS_CFG[highest["severity"]]

    embed = {
        "title": "🚨 Suspicious Activity Detected",
        "description": "Multiple security events have been detected.",
        "color": colour,
        "fields": [],
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat()
    }

    for alert in alerts:
        icon = severity_icons.get(alert.get("severity"), "⚪")

        embed["fields"].append({
            "name": f"{icon} {alert['type'].replace('_', ' ').title()}",
            "value": f"**IP:** `{alert['ip']}`\n**Reason:** {alert['reason']}\n**Time:** `{alert['time'].strftime('%Y-%m-%d %H:%M:%S')}`",
            "inline": False
        })

    payload = {"embeds": [embed]}

    try:
        requests.post(WEBHOOK_URL, json=payload)
        print("Embed alert sent to Discord.")
    except Exception as e:
        print(f"Failed to send embed alert: {e}")

#loads logs, runs all detection functions, deduplicates alerts, prints them to the console, and sends them to Discord if any are found.
def main():
    events = load_logs(LOG_FILE_PATH)

    alerts = []
    alerts += detect_bruteforce(events)
    alerts += detect_admin_access(events)
    alerts += detect_after_hours(events)
    alerts += detect_high_volume(events)
    alerts += detect_endpoint_scanning(events)
    alerts += detect_suspicious_user_agents(events)

    alerts = dedupe_alerts(alerts)

    if alerts:
        print("[!] Suspicious activity detected:")
        for alert in alerts:
            icon = SEVERITY_ICONS.get(alert["severity"], "⚪")
            print(f"{icon} IP {alert['ip']} at {alert['time']}: {alert['reason']}")

        send_alert(alerts)
    else:
        print("No suspicious activity detected.")

#runs the program by calling the main function when the script is executed directly.
if __name__ == "__main__":
    main()

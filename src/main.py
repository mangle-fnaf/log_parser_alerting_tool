import datetime

LOG_FILE_PATH = "logs/sample.log"

#Codes that will be flagged, number of attempts, checks for attacks occuring within 10 seconds of each other
FAILED_STATUS_CODES = {"401", "403"}
MAX_FAILED_ATTEMPTS = 3
TIME_WINDOW_SECONDS = 10  # e.g. 10 seconds


def parse_log_line(line):
    #splits and strips the text line
    parts = line.strip().split()
    #safety check = if there is less than 5 segments, the system skips it.
    if len(parts) < 5:
        return None

    timestamp_str = f"{parts[0]} {parts[1]}"
    ip = parts[2]
    method = parts[3]
    path = parts[4]
    status = parts[5] if len(parts) > 5 else "200"

#Converts raw timestring stamp into python datetime. If it does not match the format, it returns value none.
    try:
        timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

#organises pieces and sends it back to caller.
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

#detects brute force attacks
def detect_bruteforce(events):
    suspicious = []

    # sort by time
    events = sorted(events, key=lambda e: e["timestamp"])

#If the log entry was a successful request, it immediately skips it.
    for i, event in enumerate(events):
        if event["status"] not in FAILED_STATUS_CODES:
            continue

#window starts (10 seconds). Registers initial failed attempt.
        window_start = event["timestamp"]
        ip = event["ip"]

        failed_count = 1

#it looks through logs present after. If it belongs to the same IP, ignore it.
        for j in range(i + 1, len(events)):
            next_event = events[j]
            if next_event["ip"] != ip:
                continue

#if window more than 10 seconds, it breaks the inner loop.
            delta = (next_event["timestamp"] - window_start).total_seconds()
            if delta > TIME_WINDOW_SECONDS:
                break

            if next_event["status"] in FAILED_STATUS_CODES:
                failed_count += 1

#if the counter is more than 3, it creates an alert dictionary.
        if failed_count >= MAX_FAILED_ATTEMPTS:
            suspicious.append(
                {
                    "ip": ip,
                    "start_time": window_start,
                    "failed_count": failed_count,
                }
            )

    return suspicious

#outputs results
def main():
    events = load_logs(LOG_FILE_PATH)
    bruteforce_alerts = detect_bruteforce(events)

#if alert list is full, it prints the details.
    if bruteforce_alerts:
        print("[!] Suspicious activity detected:")
        for alert in bruteforce_alerts:
            print(
                f"- IP {alert['ip']} had {alert['failed_count']} failed attempts "
                f"starting at {alert['start_time']}"
            )
    else:
        print("No suspicious activity detected.")


if __name__ == "__main__":
    main()


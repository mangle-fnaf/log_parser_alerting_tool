# Log Parser Alerting Tool

A Python-based security monitoring tool that scans log files for suspicious activity, generates alerts, enriches alerts with GeoIP information, and sends notifications through Discord webhooks.

## Overview

This project was developed to simulate some of the core functionality performed by Security Operations Centre (SOC) analysts when investigating web server activity.

The tool parses log entries, identifies suspicious behaviour using configurable detection rules, enriches alerts with GeoIP information, and exports findings for further investigation.

## Features

### Detection Rules

- Brute Force Detection
- Admin Endpoint Access Detection
- After-Hours Activity Detection
- High Volume Request Detection
- Endpoint Scanning Detection
- Suspicious User-Agent Detection

### Alert Management

- Severity-Based Alert Classification
- Alert Deduplication
- Discord Webhook Notifications

### Alert Enrichment

- GeoIP Country Lookup
- Region Lookup
- City Lookup
- ISP Identification
- ASN Identification

### Export Options

- JSON Export
- CSV Export

### Additional Features

- Command Line Interface (CLI)
- Config Driven Rules
- Sample Detection Datasets
- Automated Testing

## Architecture

```text
Log Files
    │
    ▼
Log Parser
    │
    ▼
Detection Rules
    │
    ▼
Alert Deduplication
    │
    ▼
GeoIP Enrichment
    │
 ┌──┴───────────┬───────────┐
 ▼              ▼           ▼
JSON Export   CSV Export   Discord Alert
```

## Detection Rules

### Brute Force Detection

Detects multiple failed login attempts from the same IP address within a configurable time window.

### Admin Access Detection

Detects attempts to access administrative endpoints such as:

```text
/admin
```

### After-Hours Detection

Detects activity between:

```text
00:00 - 06:00
```

### High Volume Detection

Identifies IP addresses generating excessive request volumes within a short period.

### Endpoint Scanning Detection

Detects requests to multiple unique endpoints from the same IP address.

### Suspicious User-Agent Detection

Flags requests containing known suspicious user-agents such as:

```text
curl
python-requests
sqlmap
nmap
wget
```

## Installation

Clone the repository:

```bash
git clone https://github.com/mangle-fnaf/log_parser_alerting_tool.git
```

Navigate into the project directory:

```bash
cd log_parser_alerting_tool
```

Install dependencies:

```bash
pip install requests
```

## Usage

Run using the default configuration:

```bash
python src/main.py
```

Run a specific log file:

```bash
python src/main.py --log logs/bruteforce.log
```

Disable Discord notifications:

```bash
python src/main.py --no-discord
```

Disable JSON export:

```bash
python src/main.py --no-json
```

Disable CSV export:

```bash
python src/main.py --no-csv
```

Enable only selected rules:

```bash
python src/main.py --rules bruteforce,endpoint_scan
```

## Sample Datasets

### normal_activity.log

Contains legitimate traffic and should not generate alerts.

### bruteforce.log

Contains repeated failed login attempts from a single IP address.

### high_volume.log

Contains a high number of requests from a single IP address.

### after_hours.log

Contains activity outside normal operating hours.

### endpoint_scan.log

Contains endpoint enumeration activity.

### mixed_attacks.log

Demonstrates all major detection rules simultaneously.

## Example Output

```text
[!] Suspicious activity detected:

🔴 IP 192.168.0.10 at 2024-10-05 10:01:01:
4 failed login attempts in 10s

🟠 IP 10.0.0.5 at 2024-10-05 10:02:10:
Accessed /admin page

🟢 IP 172.16.0.20 at 2024-10-05 02:15:10:
Activity outside normal hours
```

## Testing

Run all tests:

```bash
pytest
```

Run tests with coverage:

```bash
pytest --cov=src --cov-report=term-missing
```

### Current Test Coverage

```text
73%
```

## Future Improvements

- Real-Time Log Monitoring
- Email Notifications
- Dashboard Interface
- Additional Detection Rules
- SIEM Integration

## Author

**Maliyka**

Cybersecurity Student

Built to demonstrate log analysis, alert generation, detection engineering, Python development, and security monitoring concepts.
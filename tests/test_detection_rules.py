import datetime

from src.main import (
    detect_admin_access,
    detect_after_hours,
    detect_suspicious_user_agents
)

#tests whether access attempts to admin endpoints are detected correctly.
def test_admin_access_detection():
    events = [{
        "timestamp": datetime.datetime.now(),
        "ip": "10.0.0.5",
        "method": "GET",
        "path": "/admin",
        "status": "200",
        "user_agent": "Mozilla"
    }]

    alerts = detect_admin_access(events)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "admin_access"


#tests whether events occurring during after-hours are flagged as suspicious.
def test_after_hours_detection():
    events = [{
        "timestamp": datetime.datetime(2024, 10, 5, 2, 30),
        "ip": "10.0.0.5",
        "method": "GET",
        "path": "/home",
        "status": "200",
        "user_agent": "Mozilla"
    }]

    alerts = detect_after_hours(events)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "after_hours"


#tests whether suspicious user agents such as sqlmap are detected correctly.
def test_suspicious_user_agent_detection():
    events = [{
        "timestamp": datetime.datetime.now(),
        "ip": "10.0.0.5",
        "method": "GET",
        "path": "/",
        "status": "200",
        "user_agent": "sqlmap/1.7"
    }]

    alerts = detect_suspicious_user_agents(events)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "suspicious_user_agent"

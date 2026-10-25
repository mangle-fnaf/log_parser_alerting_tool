import datetime
import os

from src.main import export_csv

#tests whether alerts can be exported to a CSV file successfully.
def test_export_csv_creates_file():
    alerts = [{
        "ip": "1.1.1.1",
        "time": datetime.datetime.now(),
        "reason": "Test Alert",
        "type": "test",
        "severity": "low"
    }]

    export_csv(alerts)

    assert os.path.exists("alerts")
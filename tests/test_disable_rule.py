from src.main import detect_admin_access

#tests whether disabled rules return no alerts.
def test_admin_rule_disabled(monkeypatch):
    from src import main

    monkeypatch.setitem(main.RULES_ENABLED, "admin_access", False)

    alerts = detect_admin_access([])

    assert alerts == []

    monkeypatch.setitem(main.RULES_ENABLED, "admin_access", True)
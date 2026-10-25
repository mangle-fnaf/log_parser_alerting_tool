#tests whether command line arguments are parsed correctly.
def test_parse_cli_args(monkeypatch):
    import sys
    from src.main import parse_cli_args

    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "--log", "logs/test.log", "--no-discord"]
    )

    args = parse_cli_args()

    assert args.log == "logs/test.log"
    assert args.no_discord is True
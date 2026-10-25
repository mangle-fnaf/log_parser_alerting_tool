from src import main

#tests whether the application handles an empty log list without raising exceptions.
def test_main_no_alerts(monkeypatch):

    monkeypatch.setattr(main, "load_logs", lambda _: [])

    monkeypatch.setattr(
        main,
        "parse_cli_args",
        lambda: type(
            "Args",
            (),
            {
                "log": None,
                "rules": None,
                "no_json": True,
                "no_csv": True,
                "no_discord": True
            }
        )()
    )

    main.main()
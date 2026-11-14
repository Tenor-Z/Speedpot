# Speedpot project structure

```text
Speedpot/
├── alerts/                    # Alert delivery and alert-settings UI
│   ├── __init__.py
│   ├── manager.py
│   └── settings_ui.py
├── attack_detection/          # Payload and port-scan detection
│   ├── __init__.py
│   ├── attack_detector.py
│   └── port_scan_detector.py
├── data/                      # Runtime SQLite databases
│   ├── honeypot.db
│   ├── port_scans.db
│   └── threat_cache.db
├── logs/                      # Runtime log files
│   └── honeypot.log
├── tests/                     # Standalone and regression tests
│   ├── __init__.py
│   ├── test_discord.py
│   └── test_sql_detection.py
├── docs/                      # Installation, usage, and structure docs
├── exports/                   # User-generated exports
├── images/                    # GUI images and application icon
├── keys/                      # Local API-key configuration
├── profiles/                  # Built-in and user profiles
├── config.json
├── paths.py                   # Central path definitions and legacy migration
├── database_manager.py
├── export_manager.py
├── geoip_manager.py
├── gui.py
├── main.py
├── options.py
└── threat_intelligence.py
```

## Runtime paths

Speedpot no longer relies on the shell's current working directory for its
primary databases and log. `paths.py` resolves paths relative to the project
folder and creates required directories automatically.

When upgrading from an older layout, root-level `honeypot.db`,
`port_scans.db`, `threat_cache.db`, and `honeypot.log` files are moved into
`data/` or `logs/` when no destination file already exists.

## Running tests

From the project root:

```powershell
python -m tests.test_sql_detection
python -m tests.test_discord
```

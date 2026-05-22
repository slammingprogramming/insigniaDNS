# insigniaDNS

`insigniaDNS` is a lightweight LAN-only DNS redirect service for the Insignia Xbox Original connectivity use-case.

It does one job:

- fetch the Insignia `dns_zones.json` zone list
- redirect those domains to the correct IPs on your local network
- forward everything else to an upstream resolver such as `1.1.1.1`

It is intentionally not a general-purpose DNS platform, dashboard, or database-backed service.

## Quick Start

Install requirements:

```shell
python -m pip install -r requirements.txt
```

Run the setup wizard:

```shell
python insigniaDNS.py --setup
```

Start the DNS service:

```shell
python insigniaDNS.py
```

On Linux and macOS, binding to port `53` usually requires `sudo` or equivalent privileges.

On your Xbox console, point custom DNS to the LAN IP shown by `insigniaDNS`.

## Default Config

If `config.json` is missing, `insigniaDNS.py` creates it automatically.

```json
{
  "listen_ip": "auto",
  "port": 53,
  "zones_url": "https://insignia.live/dns_zones.json",
  "refresh_interval_sec": 900,
  "upstream_dns": "1.1.1.1",
  "cache_enabled": true,
  "cache_ttl_sec": 300,
  "persist_cache": false,
  "metrics_enabled": false,
  "metrics_port": 9090,
  "health_print_interval": 10,
  "dns_trap_detection": true,
  "update_check_url": "https://insignia.live/version.json"
}
```

## Config Notes

- `listen_ip`: use `"auto"` to bind to the detected LAN IP. This is the recommended mode for LAN-only use.
- `port`: defaults to `53`. Changing it is supported, but consoles must also send DNS to that port.
- `zones_url`: remote Insignia zone source.
- `refresh_interval_sec`: normal refresh cadence after a successful fetch.
- `upstream_dns`: resolver used for domains outside the Insignia zone list.
- `cache_enabled`: enables in-memory response caching.
- `cache_ttl_sec`: caps how long cached entries stay fresh.
- `persist_cache`: saves cache to `dns_cache.json` on clean shutdown and reloads it on startup.
- `metrics_enabled`: exposes a lightweight HTTP `/metrics` endpoint.
- `metrics_port`: port used by the optional metrics endpoint.
- `health_print_interval`: how often health status is printed to the terminal.
- `dns_trap_detection`: enables heuristic interception checks.
- `update_check_url`: remote version metadata endpoint. This only warns; it never auto-updates.

Optional advanced config:

```json
{
  "fallback_dns": ["8.8.8.8"]
}
```

If present, `fallback_dns` is used as a retry path when the primary upstream resolver fails.

## Runtime Behavior

When a DNS request comes in:

1. If the name is in the Insignia zone file, `insigniaDNS` returns the redirected IP.
2. If it is not in the Insignia zone file, the query is forwarded to `upstream_dns`.
3. Responses are cached in memory.
4. Stale cached entries can still be served briefly while a background refresh is queued.

The server stays up even if:

- the zone endpoint is temporarily unreachable
- the upstream resolver times out
- `config.json` is invalid
- internet access is partially degraded
- the version endpoint is unavailable

## Health Output

The terminal prints periodic health snapshots like:

```text
[HEALTH]
Zones: OK (200ms)
Upstream DNS: OK (12ms)
Internet: OK (18ms)
DNS Check: OK (10ms)
Cache: 142 entries
Mode: NORMAL
Trap Detection: CLEAN (0%)
```

Mode values are designed to separate common failure cases:

- `NORMAL`
- `INTERNET_DOWN`
- `UPSTREAM_FAILURE`
- `DNS_FAILURE`
- `ZONE_FAILURE`

## DNS Trap Detection

`insigniaDNS` includes a heuristic trap check for networks that appear to intercept or rewrite DNS.

It compares selected Insignia hostnames against:

- the configured upstream DNS
- a fallback public resolver
- the expected IPs from the Insignia zone file

If enough mismatches are detected, the terminal prints a warning with a confidence percentage.

This is heuristic only. It is meant to help identify DNS behavior on a LAN, not provide an absolute verdict.

## Metrics Endpoint

If `metrics_enabled` is `true`, the service exposes:

- `http://<listen_ip>:<metrics_port>/metrics`

Exported metrics include:

- `dns_requests_total`
- `cache_hits`
- `cache_misses`
- `upstream_failures`
- `zone_refresh_success`
- `zone_refresh_failures`
- `trap_detection_score`
- `update_available`
- `cache_entries`

## Update Checks

The script compares its local version constant against the remote `version.json` payload.

Example warning:

```text
[UPDATE] New version available: 1.2.0 (current: 1.0.0)
```

There is no auto-download and no auto-update path.

## Service Install

The app still runs directly with:

```shell
python insigniaDNS.py
```

Helper files are included for service-style deployment:

- Linux systemd: [docs/systemd/insigniaDNS.service](docs/systemd/insigniaDNS.service)
- macOS launchd: [docs/launchd/com.insignia.insigniaDNS.plist](docs/launchd/com.insignia.insigniaDNS.plist)

### Linux systemd

1. Edit the working directory and Python path inside `docs/systemd/insigniaDNS.service`.
2. Copy it to `/etc/systemd/system/insigniaDNS.service`.
3. Run:

```shell
sudo systemctl daemon-reload
sudo systemctl enable --now insigniaDNS.service
sudo systemctl status insigniaDNS.service
```

### Windows

Recommended options:

- run `python insigniaDNS.py` in a background terminal
- use NSSM to wrap `python.exe` + `insigniaDNS.py` as a Windows service

Suggested NSSM values:

- Application: full path to `python.exe`
- Startup directory: repo folder
- Arguments: `insigniaDNS.py`

If Windows Firewall prompts for access, allow it on your private network.

### macOS launchd

1. Edit the paths inside `docs/launchd/com.insignia.insigniaDNS.plist`.
2. Copy it to `~/Library/LaunchAgents/` for user scope or `/Library/LaunchDaemons/` for system scope.
3. Load it:

```shell
launchctl load ~/Library/LaunchAgents/com.insignia.insigniaDNS.plist
launchctl start com.insignia.insigniaDNS
```

## Troubleshooting

- No DNS requests are arriving: confirm the console and server are on the same LAN, verify the shown LAN IP, and check local firewall rules.
- Port `53` bind fails: run with elevated privileges on Linux/macOS, or free the port from another DNS service.
- Zones fail to load: verify general internet access and test whether `https://insignia.live/dns_zones.json` is reachable.
- Unknown domains fail: test the configured `upstream_dns`, then add `fallback_dns` if you want a retry resolver.
- Trap warnings appear: try a different upstream resolver and compare results from another network if possible.
- Config changes to `listen_ip`, `port`, or metrics listener settings may require a restart to fully apply.
- Python version 3.6+ is not installed: install Python version 3.6 or higher. Tested on Python 3.9.9 
- Python binary not found: `python3` is assumed to be the name of your python binary, if it is not then it will need to be substituted with the name and/or path of your binary.

## Building on Windows

If you want a standalone executable, you can still package the script with Nuitka:

```shell
python -m pip install -r requirements.txt nuitka zstandard
python -m nuitka --standalone --onefile --windows-icon-from-ico=insigniaDNS_icon.ico -o insigniaDNS.exe insigniaDNS.py
```

## Issue Reporting
Please submit any issues either via our [Discord server](https://insig.uk/discord) or [Insignia support](https://support.insignia.live).`

## Credits

Original code created by the Sudomemo Team: [sudomemoDNS](https://github.com/Sudomemo/sudomemoDNS)

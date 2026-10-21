# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A single-page Flask web UI that wraps `nmap` (via `python-nmap`) to scan an IP or CIDR range and stream discovered hosts (OS guess, MAC/vendor, open ports with service versions) to the browser. Not a git repository; no build step, linter, or test suite.

## Environment and running

- `engine_code/` is the Python 3.12 **virtualenv**, not source code. The shell's `python3` resolves to `engine_code/bin/python3`, so `pip install` here modifies the venv the production service uses.
- Root is required: nmap runs with `-O -sV --osscan-guess`, and OS detection needs raw sockets.
- To run a dev copy without disturbing the service on :5000, use the **same environment as the systemd unit** (its `PATH` is only the venv's `bin`, so anything that shells out to a bare `nmap` works in a normal shell but fails in production; this shipped once):

  ```bash
  nohup env -i PATH=/root/workspace/network_scanner/engine_code/bin HOME=/root \
    /root/workspace/network_scanner/engine_code/bin/python -m flask --app app run --host 127.0.0.1 --port 5055 &
  ```

  Subprocess calls must use `NMAP_PATH` (python-nmap's resolved path), never `'nmap'`.

- Only scan `127.0.0.x` (every loopback address answers on Linux, so `127.0.0.0/29` gives 6 live hosts) or the reserved `192.0.2.0/24` documentation range when testing; real ranges hit actual hosts. Loopback scans probe the production app on :5000 too, which logs a burst of harmless `code 400, Bad request` errors from nmap's `-sV` probes. Check `journalctl -u networkscan` for scans in progress before restarting the service.

## Service management

Production runs as the systemd unit `networkscan` (defined in `networkscan.service`), as root, executing `app.py` with the venv's Python on `0.0.0.0:5000`. It has `Restart=always`, so killing the process just respawns it; use `systemctl` to stop it. You are permitted to stop, start, restart and check the status of this service.

```bash
systemctl status networkscan      # state, PID, recent log lines
systemctl stop networkscan
systemctl start networkscan
systemctl restart networkscan     # required after editing app.py or templates/index.html
journalctl -u networkscan -n 50   # logs (add -f to follow)
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:5000/   # health check, expect 200
```

If the unit file itself is edited, copy it to `/etc/systemd/system/networkscan.service` (where it is installed) and run `systemctl daemon-reload` before restarting.

## Architecture

All backend logic is in `app.py`; all frontend (HTML, CSS, JS) is inline in `templates/index.html`.

Scan flow:

1. Input is a list of targets separated by commas, spaces, `;` or newlines: single IPs, CIDR blocks (hosts only, like `ipaddress.hosts()`), `10.0.0.1-50` or `10.0.0.1-10.0.1.5`. `parse_targets()` in `app.py` turns them into sorted, merged `(first, last)` int ranges, capped at `MAX_TARGETS` (65,536). `parseTargets()` in the template mirrors it exactly (the address map's cell positions depend on the same order), so change both together. The page validates client-side, then confirms with `POST /validate`.
2. `GET /scan/stream?network=...` is a **Server-Sent Events** endpoint. It registers a `scan_id` in the module-global `active_scans` dict, starts `scan_network_streaming` in a daemon thread, and relays messages from a `Queue` to the client.
3. The worker runs in two phases. **Sweep:** `nmap -sn` over the range in chunks of `SWEEP_CHUNK` (256) addresses, excluding the machine's own outbound IP (`get_local_ip`). `--min-rate 500` is essential: without it nmap backs off to ~2.5 hosts/s when few hosts reply (a dead /24 took 103 s instead of 5 s). **Detail:** each live host gets its own scan with `DETAIL_ARGS[mode]`: `full` is `-Pn -O -sV --osscan-guess -T4`, `quick` adds `--version-light` (passed as `?mode=` on `/scan/stream`) on a `ThreadPoolExecutor` of `DETAIL_WORKERS` (8). `run_detail_scan` runs nmap via `subprocess` (not `PortScanner.scan`, which blocks until the end) with `-v --stats-every 2s -oX <tempfile>`, parses "Discovered open port" and "Timing: About N% done" lines from stdout as they arrive, then loads the XML with `PortScanner.analyse_nmap_xml_scan` for the final result. `-sV` dominates the cost: port discovery takes seconds, but every unrecognised service (shown with `?`) makes nmap exhaust all probes, so hosts with many custom ports take 2–3 min (loopback: 115 s Full vs 26 s Quick). MAC/vendor are merged from the sweep (ARP) if the detail scan lacks them.
4. Events: `started`, `status`, `checking` (`phase: sweep` with first/last of the chunk, or `phase: detail` with one IP; drives the blinking cells), `swept` (chunk range + `live` IPs + running totals), `port` (open port as nmap finds it), `stage` (`ports`/`services`/`os` + optional percent), `host` (final result; replaces the pending row), `complete`, `error`, `cancelled`. `handleScanEvent` in the template switches on the same `type` values; keep both sides in sync when changing the event schema.
5. Cancellation: `POST /scan/cancel/<scan_id>` deletes the ID from `active_scans`. The worker checks it between sweep chunks and once a second while detail scans run; a watcher thread kills each running detail nmap within 0.5 s, queued ones are dropped. The SSE generator also removes the scan from `active_scans` when the browser disconnects, so closing the tab stops the scan.
6. Search, sort and Excel export are purely client-side over the `allResults` array / table rows. Export lazy-loads SheetJS from `cdn.sheetjs.com` on first click.
7. The "address map" grid has one cell per position in the merged target list (`addressAt` / `cellIndex` convert between positions and IPs across ranges), capped at 256 cells, so large scans get one cell per block of addresses.

Host data comes from nmap (reverse-DNS names, service banners), which scanned devices control, so the template builds table cells with `textContent`; never interpolate it into `innerHTML`.

## Backups

`backup/` holds copies that nothing runs or imports; don't edit them when changing behavior.

- `backup/app_copy.py` and `backup/index copy.html`: the original non-streaming version (single blocking `POST /scan` over the whole range).
- `backup/2026-10-21/`: snapshots taken before each change that day: `index.original.html` (the pre-redesign UI), `app.before-twophase.py` (batches of 5), `app.before-portstream.py`, `app.before-multitarget.py`, `index.before-multitarget.html`.

## UI testing

Playwright + headless Chromium are installed in the venv (`python3 -m playwright install chromium-headless-shell`; `--with-deps` fails on this RHEL host because it expects apt). Flask caches templates when not in debug mode, so restart the dev server (as well as the service) after editing `index.html`, or tests will run against the old page.

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A single-page Flask web UI that wraps `nmap` (via `python-nmap`) to scan an IP or CIDR range and stream discovered hosts (OS guess, MAC/vendor, open ports with service versions) to the browser. Not a git repository; no build step, linter, or test suite.

## Environment and running

- Production on this server runs as the **`network-scanner` Docker container** (see "Service management"). `engine_code/` is a Python 3.12 **virtualenv**, not source code, used for the dev server and Playwright tests; the shell's `python3` resolves to it.
- Root is required: nmap runs with `-O -sV --osscan-guess`, and OS detection needs raw sockets.
- To run a dev copy without disturbing production on :5000, use a **minimal `PATH`** like the old systemd unit had (only the venv's `bin`), so anything that shells out to a bare `nmap` fails in testing instead of in production; this shipped once. Before deploying, also test the built image (see "Container"):

  ```bash
  nohup env -i PATH=/root/workspace/network_scanner/engine_code/bin HOME=/root \
    /root/workspace/network_scanner/engine_code/bin/python -m flask --app app run --host 127.0.0.1 --port 5055 &
  ```

  Subprocess calls must use `NMAP_PATH` (python-nmap's resolved path), never `'nmap'`.

- Only scan `127.0.0.x` (every loopback address answers on Linux, so `127.0.0.0/29` gives 6 live hosts) or the reserved `192.0.2.0/24` documentation range when testing; real ranges hit actual hosts. Loopback scans probe the production app on :5000 too, which logs a burst of harmless `code 400, Bad request` errors from nmap's `-sV` probes. Check `docker logs network-scanner` for scans in progress before restarting.

## Container

`Dockerfile` (python:3.12-slim-bookworm + Debian's nmap, gunicorn `gthread` with **one worker** and 64 threads: `active_scans` is in-process state, and each SSE stream holds a thread for its scan) and `docker-compose.yml` (`network_mode: host`, `cap_drop: ALL`, `cap_add: NET_RAW`). Tested: `NET_RAW` alone covers SYN scan, OS detection and ARP; `NET_ADMIN` and `--privileged` aren't needed. Host networking is what gives MAC/vendor and ARP discovery; on a bridge network scans work but go through NAT. `HOST`/`PORT` env vars set the bind address. README.md has the user-facing run instructions.

To test an image without touching the service on :5000, run it on another port with host networking, e.g. `docker run -d --name ns-test --network host -e PORT=5056 --cap-drop ALL --cap-add NET_RAW <image>`, and point the Playwright tests at 5056.

## Service management

Production runs as the Docker container `network-scanner`, defined by `docker-compose.yml` in this directory (host networking, port 5000, `restart: unless-stopped`; Docker is enabled at boot). You are permitted to stop, start, restart, rebuild and check the status of this container.

```bash
docker compose ps                         # state and health
docker compose logs -f --tail 50          # logs ("Starting full/quick scan", "Scan complete")
docker compose up -d --build              # deploy: rebuild the image and recreate the container (required after any code change)
docker compose restart
docker compose stop / docker compose start
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:5000/   # health check, expect 200
```

The old systemd unit (`networkscan.service`, installed at `/etc/systemd/system/networkscan.service`) is kept **stopped and disabled** for rollback: `docker compose down && systemctl enable --now networkscan`. Never run both: they share port 5000.

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

# Network scanner

A web UI for [nmap](https://nmap.org). Enter IP addresses, CIDR blocks or ranges and watch live hosts appear, with open ports streaming in as nmap finds them, then services, versions and an OS guess.

- Fast two-phase scan: a quick sweep finds live hosts, then each one gets a detailed scan in parallel
- Several targets at once: `10.0.0.0/24, 10.0.1.5-40 192.168.1.10`
- Full or Quick detail (Quick is about 5× faster; rare services get a guessed name only)
- Address map with live progress, scan timer, filter, sort and Excel export

Only scan networks you own or have permission to scan.

## Run with Docker Compose

Requires Linux with Docker and the Compose plugin.

```bash
git clone https://github.com/babithg/network-scanner.git
cd network-scanner
docker compose up -d --build
```

Open `http://<host>:5000`. To use another port, change `PORT` in `docker-compose.yml`.

## Run with `docker run`

```bash
docker build -t network-scanner .
docker run -d --name network-scanner --restart unless-stopped \
  --network host \
  --cap-drop ALL --cap-add NET_RAW \
  -e PORT=5000 \
  network-scanner
```

### Why host networking and `NET_RAW`

- **`NET_RAW`** lets nmap open raw sockets for SYN port scans, OS detection and ARP discovery. No other capability is needed, and `--privileged` is not required.
- **`--network host`** puts the container directly on the host's network, so nmap can ARP-sweep the local subnet and report **MAC addresses and vendors**.

On Docker's default bridge network (or Docker Desktop on macOS/Windows, where host networking is limited), publish the port instead:

```bash
docker run -d --name network-scanner -p 5000:5000 --cap-drop ALL --cap-add NET_RAW network-scanner
```

Scanning still works, but traffic goes through Docker's NAT: MAC addresses and vendors won't be shown, and finding hosts on the local subnet is slower. `127.0.0.1` then means the container itself, not the host.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `5000` | Port the web UI listens on |
| `HOST` | `0.0.0.0` | Address to bind; set to one interface's IP to limit who can reach it |

## Security

The app has **no login**. Anyone who can reach the port can scan any address the host can reach, with raw-socket access. Run it only on a trusted network, or put it behind a reverse proxy with authentication or a VPN.

The browser loads fonts from Google Fonts and the Excel export library from `cdn.sheetjs.com`; without internet access the page still works, with fallback fonts and no Excel export.

## Without Docker

`networkscan.service` runs `app.py` directly with systemd from a virtualenv in `engine_code/`:

```bash
python3 -m venv engine_code
engine_code/bin/pip install -r requirements.txt
sudo dnf install nmap        # or: apt install nmap
cp networkscan.service /etc/systemd/system/ && systemctl daemon-reload && systemctl enable --now networkscan
```

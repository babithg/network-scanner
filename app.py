from flask import Flask, render_template, request, jsonify, Response
import nmap
import ipaddress
import logging
import socket
import json
import threading
import time
import re
import subprocess
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor, wait
from queue import Queue, Empty

app = Flask(__name__)

# Suppress werkzeug's noisy logging for bad requests (nmap probes)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Custom logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('NetworkScanner')

# Store for active scans
active_scans = {}

def get_local_ip():
    """Get the local IP address of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return None

MAX_TARGETS = 65536

def parse_target(token):
    """Turn one target into an inclusive (first, last) range of IPv4 addresses as ints.
    Accepts 10.0.0.5, 10.0.0.0/24 (hosts only, like ipaddress.hosts()), 10.0.0.5-20 and 10.0.0.5-10.0.1.20."""
    if '-' in token:
        start_text, end_text = token.split('-', 1)
        start = ipaddress.IPv4Address(start_text)
        if end_text.isdigit():
            end_text = start_text.rsplit('.', 1)[0] + '.' + end_text
        end = ipaddress.IPv4Address(end_text)
        if end < start:
            raise ValueError(f"“{token}” ends before it starts")
        return int(start), int(end)
    
    network = ipaddress.IPv4Network(token, strict=False)
    if network.prefixlen >= 31:
        return int(network.network_address), int(network.broadcast_address)
    return int(network.network_address) + 1, int(network.broadcast_address) - 1

def parse_targets(text):
    """Parse comma/space/newline separated targets into sorted, merged (first, last) ranges.
    Raises ValueError with a message naming the bad target. Mirrored by parseTargets() in index.html."""
    tokens = [t for t in re.split(r'[\s,;]+', text.strip()) if t]
    if not tokens:
        raise ValueError("Enter at least one address or range")
    
    ranges = []
    for token in tokens:
        try:
            ranges.append(parse_target(token))
        except ValueError as e:
            if str(e).startswith(f"“{token}”"):
                raise
            raise ValueError(f"“{token}” isn't a valid IPv4 address, range or CIDR block") from e
    
    merged = []
    for first, last in sorted(ranges):
        if merged and first <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], last))
        else:
            merged.append((first, last))
    
    total = sum(last - first + 1 for first, last in merged)
    if total > MAX_TARGETS:
        raise ValueError(f"That's {total:,} addresses; the limit is {MAX_TARGETS:,} per scan")
    return merged

def scan_host(nm, host):
    """Extract host information from nmap scan results."""
    host_info = {
        'ip': host,
        'hostname': nm[host].hostname() or 'N/A',
        'state': nm[host].state(),
        'os': 'Unknown',
        'os_accuracy': 'N/A',
        'mac': 'N/A',
        'vendor': 'N/A',
        'open_ports': []
    }
    
    # Get OS information
    if 'osmatch' in nm[host] and nm[host]['osmatch']:
        os_match = nm[host]['osmatch'][0]
        host_info['os'] = os_match.get('name', 'Unknown')
        host_info['os_accuracy'] = f"{os_match.get('accuracy', 'N/A')}%"
    
    # Get MAC address and vendor
    if 'addresses' in nm[host]:
        if 'mac' in nm[host]['addresses']:
            host_info['mac'] = nm[host]['addresses']['mac']
    
    if 'vendor' in nm[host] and nm[host]['vendor']:
        host_info['vendor'] = list(nm[host]['vendor'].values())[0] if nm[host]['vendor'] else 'N/A'
    
    # Get open ports
    for proto in nm[host].all_protocols():
        ports = nm[host][proto].keys()
        for port in ports:
            port_info = nm[host][proto][port]
            if port_info['state'] == 'open':
                host_info['open_ports'].append({
                    'port': port,
                    'service': port_info.get('name', 'unknown'),
                    'version': port_info.get('version', '')
                })
    
    return host_info

# Phase 1 sweeps the range for live hosts in chunks (keeps cancel and progress responsive);
# phase 2 runs the slow OS/service detection only on live hosts, several at once.
SWEEP_CHUNK = 256
SWEEP_ARGS = "-sn -T4 --min-rate 500"  # without a floor, nmap backs off to ~2.5 hosts/s on ranges with few replies
DETAIL_WORKERS = 8
# Quick mode only sends the most likely service probes: ~5x faster, rarer services get a guessed name only
DETAIL_ARGS = {
    'full': "-Pn -O -sV --osscan-guess -T4",
    'quick': "-Pn -O -sV --version-light --osscan-guess -T4",
}

DISCOVERED_PORT = re.compile(r'^Discovered open port (\d+)/(\w+) on ')
STAGE_TIMING = re.compile(r'^(.+?) Timing: About ([\d.]+)% done')

def stage_for(text):
    """Map an nmap phase name to the stage shown in the UI."""
    if 'SYN Stealth Scan' in text or 'Connect Scan' in text:
        return 'ports'
    if 'Service scan' in text or 'NSE' in text:
        return 'services'
    if 'OS detection' in text:
        return 'os'
    return None

# The systemd unit's PATH only has the venv's bin, so a bare 'nmap' isn't found there.
# Reuse the path python-nmap resolved (it also searches /usr/bin, /usr/local/bin, ...).
NMAP_PATH = nmap.PortScanner()._nmap_path

def run_detail_scan(ip, args, emit, cancelled):
    """Run nmap on one host, emitting open ports and stage progress as nmap reports them.
    Returns a PortScanner loaded with the final results, or None if the scan was cancelled."""
    with tempfile.NamedTemporaryFile(suffix='.xml') as xml:
        cmd = [NMAP_PATH, *args.split(), '-v', '--stats-every', '2s', '-oX', xml.name, ip]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        def kill_on_cancel():
            while proc.poll() is None:
                if cancelled():
                    proc.kill()
                    return
                time.sleep(0.5)
        threading.Thread(target=kill_on_cancel, daemon=True).start()
        
        try:
            for line in proc.stdout:
                if cancelled():
                    return None
                line = line.strip()
                match = DISCOVERED_PORT.match(line)
                if match:
                    emit({'type': 'port', 'ip': ip, 'port': int(match[1]), 'protocol': match[2]})
                elif line.startswith('Initiating '):
                    stage = stage_for(line)
                    if stage:
                        emit({'type': 'stage', 'ip': ip, 'stage': stage})
                else:
                    match = STAGE_TIMING.match(line)
                    if match and stage_for(match[1]):
                        emit({'type': 'stage', 'ip': ip, 'stage': stage_for(match[1]), 'percent': float(match[2])})
            proc.wait()
            if cancelled():
                return None
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        
        nm = nmap.PortScanner()
        with open(xml.name) as f:
            nm.analyse_nmap_xml_scan(f.read())
        return nm

def scan_network_streaming(targets, ranges, mode, result_queue, scan_id):
    """Scan network and put results in queue as they're found."""
    exclude = ""
    local_ip = get_local_ip()
    if local_ip:
        exclude = f" --exclude {local_ip}"
        logger.info(f"Excluding local IP from scan: {local_ip}")
    
    lock = threading.Lock()
    counts = {'live': 0, 'found': 0}
    executor = ThreadPoolExecutor(max_workers=DETAIL_WORKERS)
    
    def cancelled():
        return scan_id not in active_scans
    
    def detail_scan(ip, sweep_info):
        if cancelled():
            return
        result_queue.put({'type': 'checking', 'phase': 'detail', 'first': ip, 'last': ip, 'data': sweep_info})
        
        host_info = None
        detail_error = None
        try:
            nm = run_detail_scan(ip, DETAIL_ARGS[mode], result_queue.put, cancelled)
            if nm is None:
                return
            if ip in nm.all_hosts():
                host_info = scan_host(nm, ip)
            else:
                detail_error = "host stopped responding during the detailed scan"
        except Exception as e:
            logger.warning(f"Error scanning {ip}: {e}")
            detail_error = str(e)
        
        if host_info is None:
            # The sweep saw it up, so still report it with what the sweep found, and say why details are missing
            host_info = dict(sweep_info, detail_error=detail_error)
        else:
            # MAC and vendor come from ARP during the sweep; keep them if the detail scan lacks them
            for key in ('mac', 'vendor'):
                if host_info[key] == 'N/A':
                    host_info[key] = sweep_info[key]
        
        with lock:
            counts['found'] += 1
            found = counts['found']
        result_queue.put({'type': 'host', 'data': host_info, 'found': found})
        logger.info(f"Found host: {ip}")
    
    try:
        logger.info(f"Starting {mode} scan on {targets}")
        
        hosts = [str(ipaddress.IPv4Address(n)) for first, last in ranges for n in range(first, last + 1)]
        
        total_hosts = len(hosts)
        swept = 0
        futures = []
        
        result_queue.put({
            'type': 'status',
            'total': total_hosts
        })
        
        for i in range(0, total_hosts, SWEEP_CHUNK):
            if cancelled():
                break
            
            chunk = hosts[i:i + SWEEP_CHUNK]
            result_queue.put({'type': 'checking', 'phase': 'sweep', 'first': chunk[0], 'last': chunk[-1]})
            
            live = {}
            try:
                nm = nmap.PortScanner()
                nm.scan(hosts=' '.join(chunk), arguments=SWEEP_ARGS + exclude)
                chunk_set = set(chunk)
                for host in sorted(nm.all_hosts(), key=ipaddress.ip_address):
                    if host in chunk_set and nm[host].state() == 'up':
                        live[host] = scan_host(nm, host)
            except Exception as e:
                logger.warning(f"Error sweeping {chunk[0]}-{chunk[-1]}: {e}")
            
            swept += len(chunk)
            with lock:
                counts['live'] += len(live)
                live_total = counts['live']
            result_queue.put({
                'type': 'swept',
                'first': chunk[0],
                'last': chunk[-1],
                'live': list(live),
                'swept': swept,
                'total': total_hosts,
                'live_total': live_total
            })
            
            for host, sweep_info in live.items():
                futures.append(executor.submit(detail_scan, host, sweep_info))
        
        # Wait for detail scans, checking for cancellation while they run
        pending = futures
        while pending and not cancelled():
            _, pending = wait(pending, timeout=1)
        
        if cancelled():
            logger.info(f"Scan {scan_id} cancelled")
            result_queue.put({'type': 'cancelled'})
            return
        
        result_queue.put({
            'type': 'complete',
            'total_found': counts['found'],
            'total_scanned': swept
        })
        logger.info(f"Scan complete. Found {counts['found']} hosts out of {swept} scanned.")
        
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        result_queue.put({
            'type': 'error',
            'message': str(e)
        })
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
        if scan_id in active_scans:
            del active_scans[scan_id]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/validate', methods=['POST'])
def validate():
    """API endpoint for input validation."""
    data = request.get_json()
    try:
        ranges = parse_targets(data.get('network', ''))
    except ValueError as e:
        return jsonify({'valid': False, 'error': str(e)})
    host_count = sum(last - first + 1 for first, last in ranges)
    return jsonify({'valid': True, 'host_count': host_count})

@app.route('/scan/stream')
def scan_stream():
    """SSE endpoint for streaming scan results."""
    network = request.args.get('network', '').strip()
    mode = request.args.get('mode', 'full')
    
    try:
        if mode not in DETAIL_ARGS:
            raise ValueError(f"Unknown scan mode “{mode}”")
        ranges = parse_targets(network)
    except ValueError as e:
        def error_stream():
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        return Response(error_stream(), mimetype='text/event-stream')
    
    scan_id = uuid.uuid4().hex
    result_queue = Queue()
    active_scans[scan_id] = True
    
    # Start scan in background thread
    thread = threading.Thread(
        target=scan_network_streaming,
        args=(network, ranges, mode, result_queue, scan_id)
    )
    thread.daemon = True
    thread.start()
    
    def generate():
        try:
            yield f"data: {json.dumps({'type': 'started', 'scan_id': scan_id})}\n\n"
            
            while True:
                try:
                    result = result_queue.get(timeout=300)  # 5 minute timeout
                except Empty:
                    yield f"data: {json.dumps({'type': 'error', 'message': 'Scan timeout'})}\n\n"
                    break
                yield f"data: {json.dumps(result)}\n\n"
                
                if result['type'] in ['complete', 'error', 'cancelled']:
                    break
        finally:
            # Browser went away (or scan ended): nobody can receive results, so stop scanning
            active_scans.pop(scan_id, None)
    
    return Response(generate(), mimetype='text/event-stream',
                   headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

@app.route('/scan/cancel/<scan_id>', methods=['POST'])
def cancel_scan(scan_id):
    """Cancel an active scan."""
    if scan_id in active_scans:
        del active_scans[scan_id]
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Scan not found'})

if __name__ == '__main__':
    logger.info("Starting Network Scanner on http://0.0.0.0:5000")
    logger.info("Note: Run with sudo for OS detection to work properly")
    app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)
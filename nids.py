#!/usr/bin/env python3
"""
---------------------------------------------------------
Detects:
  SYN flood / SYN scan
  TCP NULL, FIN, XMAS scans
  ACK scans, RST floods
  UDP scans
  ICMP ping sweeps
  Large packet anomalies

Usage for linux:
    sudo python3 nids.py --iface eth0
    sudo python3 nids.py --pcap --pcap-mode alerts --debug
Usage for windows:
    python nids.py --iface Ethernet0
Outputs:
    Console alerts with color coding
    JSON alert log file
    PCAP evidence files for each alert
Logs:
    logs/ids_alerts.json
    logs/evidence_<TAG>_<timestamp>.pcap
"""

import argparse, os, json, time, threading, shutil, signal, psutil, atexit
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import sniff, IP, TCP, UDP, ICMP, AsyncSniffer, wrpcap

# ============ Config ============
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
ALERT_LOG = os.path.join(LOG_DIR, "ids_alerts.json")
PCAP_PREFIX = os.path.join(LOG_DIR, "evidence")
MAX_LOG_FILES = 10      # keep recent 10 alert logs

DEFAULTS = dict(
    window=5,
    syn_th=150,         
    ports_th=100,        
    udp_ports_th=100,    
    icmp_hosts_th=50,
    rst_th=150,         
    ack_th=150,       
    large_pkt_threshold=1500,
)

# ============ Runtime ============
syn_times = defaultdict(deque)
tcp_ports_seen = defaultdict(lambda: defaultdict(deque))
udp_ports_seen = defaultdict(lambda: defaultdict(deque))
icmp_hosts_seen = defaultdict(deque)
rst_counts = defaultdict(deque)
ack_times = defaultdict(deque)

alert_counter = 0
packet_counter = 0
last_seen = time.time()
lock = threading.Lock()

# ============ PCAP session ============
PCAP_ENABLED = False
PCAP_MODE = None
PCAP_TEMP_FILE = None
PCAP_START_TS = None
PCAP_FINAL_FILE = None

# ============ Color helpers ============
def c(text, color):
    codes = dict(r=31, g=32, y=33, b=34, m=35, c=36, w=37)
    return f"\033[{codes.get(color,37)}m{text}\033[0m"

# ============ Utility ============
def now_ts(): return time.time()

def cleanup_deque(dq, window):
    cutoff = now_ts() - window
    while dq:
        # Check the item to see if it's a tuple or a float
        item = dq[0]
        
        # Get the timestamp, whether it's the float itself or the first part of the tuple
        ts_to_check = item[0] if isinstance(item, tuple) else item
        
        if ts_to_check < cutoff:
            dq.popleft()
        else:
            # The first item is new, so the rest must be too. Stop checking.
            break

def write_packet_to_pcap(pkt):
    if not PCAP_ENABLED or not PCAP_TEMP_FILE: return
    try: wrpcap(PCAP_TEMP_FILE, pkt, append=True)
    except Exception as e: print("[WARN] pcap write failed:", e)

def save_alert(alert):
    global alert_counter
    alert['ts'] = time.strftime("%Y-%m-%d %H:%M:%S")
    with lock:
        alert_counter += 1
        alert['id'] = alert_counter
        # colored console print
        sev_color = {'HIGH':'r','MEDIUM-HIGH':'y','MEDIUM':'b'}.get(alert['severity'],'w')
        print(c(f"[ALERT #{alert_counter}] {alert['type']} from {alert.get('src','?')} → {alert.get('dst','?')} ({alert['severity']})", sev_color))
        with open(ALERT_LOG, "a") as f:
            f.write(json.dumps(alert) + "\n")

def save_evidence(pkt, tag):
    # This now *only* writes to the single session PCAP file
    write_packet_to_pcap(pkt)
    return PCAP_TEMP_FILE

def list_interfaces():
    addrs = psutil.net_if_addrs()
    print("Available network interfaces:")
    for i,(iface, addrlist) in enumerate(addrs.items(),1):
        ips = [a.address for a in addrlist if hasattr(a,'address')]
        print(f" {i}. {iface} → {', '.join(ips)}")
    return list(addrs.keys())

def inactivity_monitor(timeout=6):
    global last_seen
    while True:
        time.sleep(timeout)
        if now_ts() - last_seen > timeout:
            print(c(f"[DEBUG] No packets in last {timeout}s. Check iface or traffic.",'c'))

def init_pcap(mode):
    global PCAP_ENABLED, PCAP_MODE, PCAP_TEMP_FILE, PCAP_START_TS
    PCAP_MODE = mode
    PCAP_ENABLED = True
    PCAP_START_TS = int(time.time())
    PCAP_TEMP_FILE = f"{PCAP_PREFIX}_running_{PCAP_START_TS}.pcap"
    open(PCAP_TEMP_FILE, "wb").close()
    print(c(f"[INFO] PCAP logging enabled ({mode}) → {PCAP_TEMP_FILE}",'y'))

def finalize_pcap():
    global PCAP_ENABLED, PCAP_TEMP_FILE, PCAP_FINAL_FILE
    if not PCAP_ENABLED or not PCAP_TEMP_FILE: return
    end_ts = int(time.time())
    start_str = time.strftime("%Y%m%d-%H%M%S", time.localtime(PCAP_START_TS))
    end_str = time.strftime("%Y%m%d-%H%M%S", time.localtime(end_ts))
    final_name = f"{PCAP_PREFIX}_{start_str}_to_{end_str}.pcap"
    try:
        if os.path.getsize(PCAP_TEMP_FILE) > 0:
            shutil.move(PCAP_TEMP_FILE, final_name)
            PCAP_FINAL_FILE = final_name
            print(c(f"[INFO] PCAP saved → {final_name}",'g'))
        else:
            os.remove(PCAP_TEMP_FILE)
            print("[INFO] No PCAP data captured.")
    except Exception as e:
        print("[WARN] finalize PCAP failed:", e)
    finally:
        PCAP_ENABLED = False

def rotate_logs():
    files = sorted([f for f in os.listdir(LOG_DIR) if f.startswith("ids_alerts")], key=lambda x: os.path.getmtime(os.path.join(LOG_DIR, x)))
    if len(files) > MAX_LOG_FILES:
        for f in files[:-MAX_LOG_FILES]:
            os.remove(os.path.join(LOG_DIR, f))

# ============ Detection ============
def analyze_packet(pkt, cfg, debug=False):
    global last_seen, packet_counter
    last_seen = now_ts()
    packet_counter += 1

    if debug:
        print(c(f"[PKT] {pkt.summary()}", 'c'))

    if PCAP_ENABLED and PCAP_MODE == "all":
        write_packet_to_pcap(pkt)
    if not pkt.haslayer(IP):
        return

    ip = pkt[IP]
    src, dst = ip.src, ip.dst
    ts = now_ts()

    # Large packet
    if len(pkt) > cfg['large_pkt_threshold']:
        save_alert({"type":"LARGE_PACKET","src":src,"dst":dst,"size":len(pkt),"severity":"MEDIUM","pcap":save_evidence(pkt,"largepkt")})

    # ICMP Ping Sweep
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        dq = icmp_hosts_seen[src]; dq.append((ts,dst))
        cleanup_deque(dq, cfg['window'])
        if len({h for _,h in dq}) >= cfg['icmp_hosts_th']:
            save_alert({"type":"PING_SWEEP","src":src,"unique_hosts":len({h for _,h in dq}),
                        "severity":"MEDIUM","pcap":save_evidence(pkt,"pingsweep")})
            dq.clear()

    # UDP scan
    if pkt.haslayer(UDP):
        dport = pkt[UDP].dport
        dq = udp_ports_seen[src][dport]; dq.append(ts)
        cleanup_deque(dq, cfg['window'])
        unique_ports = [p for p,dd in udp_ports_seen[src].items() if dd and now_ts()-dd[-1]<=cfg['window']]
        if len(unique_ports) >= cfg['udp_ports_th']:
            save_alert({"type":"UDP_PORT_SCAN","src":src,"unique_ports":len(unique_ports),
                        "severity":"MEDIUM","pcap":save_evidence(pkt,"udp_scan")})
            udp_ports_seen[src].clear()

    # TCP scans
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]; flags = int(tcp.flags); dport = tcp.dport
        # SYN scan
        if flags & 0x02:
            dq = syn_times[src]; dq.append(ts); cleanup_deque(dq, cfg['window'])
            if len(dq) >= cfg['syn_th']:
                save_alert({"type":"SYN_ACTIVITY","src":src,"count_in_window":len(dq),
                            "severity":"HIGH","pcap":save_evidence(pkt,"syn_activity")})
                dq.clear()
            # port scan
            portdq = tcp_ports_seen[src][dport]; portdq.append(ts); cleanup_deque(portdq, cfg['window'])
            unique_ports = [p for p,dd in tcp_ports_seen[src].items() if dd and now_ts()-dd[-1]<=cfg['window']]
            if len(unique_ports) >= cfg['ports_th']:
                save_alert({"type":"TCP_PORT_SCAN","src":src,"unique_ports":len(unique_ports),
                            "severity":"MEDIUM-HIGH","pcap":save_evidence(pkt,"tcp_port_scan")})
                tcp_ports_seen[src].clear()
        # RST flood
        if flags & 0x04:
            dq = rst_counts[src]; dq.append(ts); cleanup_deque(dq, cfg['window'])
            if len(dq) >= cfg['rst_th']:
                save_alert({"type":"RST_ACTIVITY","src":src,"count":len(dq),
                            "severity":"MEDIUM","pcap":save_evidence(pkt,"rst_activity")})
                dq.clear()
        # ACK scan
        if (flags & 0x10) and flags not in (0x12,0x14,0x18,0x1C,0x29):
            dq = ack_times[src]; dq.append(ts); cleanup_deque(dq, cfg['window'])
            if len(dq) >= cfg['ack_th']:
                save_alert({"type":"ACK_SCAN","src":src,"count":len(dq),
                            "severity":"MEDIUM","pcap":save_evidence(pkt,"ack_scan")})
                dq.clear()
        # NULL / FIN / XMAS
        if flags == 0x00:
            save_alert({"type":"NULL_SCAN_PKT","src":src,"dst_port":dport,"severity":"MEDIUM","pcap":save_evidence(pkt,"null")})
        if flags == 0x01:
            save_alert({"type":"FIN_SCAN_PKT","src":src,"dst_port":dport,"severity":"MEDIUM","pcap":save_evidence(pkt,"fin")})
        if (flags & 0x29) == 0x29:
            save_alert({"type":"XMAS_SCAN_PKT","src":src,"dst_port":dport,"severity":"MEDIUM","pcap":save_evidence(pkt,"xmas")})

# ============ Main ============
def main():
    parser = argparse.ArgumentParser(description="Simple heuristic NIDS.")
    parser.add_argument("--iface", help="Interface to sniff (e.g., eth0)")
    parser.add_argument("--window", type=int, default=DEFAULTS['window'])
    parser.add_argument("--syn-threshold", type=int, default=DEFAULTS['syn_th'])
    parser.add_argument("--ports-threshold", type=int, default=DEFAULTS['ports_th'])
    parser.add_argument("--udp-ports-threshold", type=int, default=DEFAULTS['udp_ports_th'])
    parser.add_argument("--icmp-hosts-threshold", type=int, default=DEFAULTS['icmp_hosts_th'])
    parser.add_argument("--rst-threshold", type=int, default=DEFAULTS['rst_th'])
    parser.add_argument("--ack-threshold", type=int, default=DEFAULTS['ack_th'])
    parser.add_argument("--large-pkt", type=int, default=DEFAULTS['large_pkt_threshold'])
    parser.add_argument("--debug", action="store_true", help="print every packet summary")
    args = parser.parse_args()

    rotate_logs()
    cfg = {
        'window': args.window,
        'syn_th': args.syn_threshold,
        'ports_th': args.ports_threshold,
        'udp_ports_th': args.udp_ports_threshold,
        'icmp_hosts_th': args.icmp_hosts_threshold,
        'rst_th': args.rst_threshold,
        'ack_th': args.ack_threshold,
        'large_pkt_threshold': args.large_pkt,
    }

# Always start the single PCAP log for alerts
    init_pcap("alerts")

    iface = args.iface or None
    if not iface:
        ifaces = list_interfaces()
        ch = input("Select interface # (Enter=all): ").strip()
        if ch: 
            try: iface = ifaces[int(ch)-1]
            except: print("Invalid → all interfaces")

    print(c(f"\n[INFO] Starting NIDS @ {datetime.now()} on {iface or 'ALL'}",'g'))
    print(c(f" Thresholds: SYN={cfg['syn_th']} PORTS={cfg['ports_th']} WINDOW={cfg['window']}s",'b'))
    t = threading.Thread(target=inactivity_monitor, daemon=True); t.start()

    def sig_handler(sig, frame):
        print("\n[INFO] Caught signal, finalizing...")
        finalize_pcap()
        print(c(f"[INFO] Sniffed {packet_counter} packets, raised {alert_counter} alerts.",'y'))
        raise KeyboardInterrupt()

    for s in (signal.SIGINT, signal.SIGTERM):
        try: signal.signal(s, sig_handler)
        except Exception: pass
    atexit.register(finalize_pcap)

    try:
        sniffer = AsyncSniffer(iface=iface, prn=lambda p: analyze_packet(p, cfg, args.debug), store=False)
        sniffer.start()
        print(c("[INFO] Sniffing started. Press Ctrl+C to stop.\n",'y'))
        while True: time.sleep(1)
    except KeyboardInterrupt:
        sniffer.stop()
    except PermissionError:
        print(c("Permission error: run as root.",'r'))
    except Exception as e:
        print(c(f"[ERROR] {e}",'r'))

if __name__ == "__main__":
    main()

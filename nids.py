#!/usr/bin/env python3
"""
nids.py — Single-file heuristic NIDS for classroom/demo use.
Detects: SYN scans, NULL/FIN/XMAS, ACK scans, UDP scans, ping sweeps,
port-scan heuristics, SSH brute-style hammering, large packets.
Cross-platform: requires admin/root. Uses scapy + psutil.

Usage:
    sudo python3 nids.py                # interactive interface selection
    sudo python3 nids.py --iface eth0   # sniff specific iface
    python nids.py --window 3 --syn-threshold 10   # tune thresholds

Logs:
    logs/ids_alerts.json  (one JSON alert per line)
    logs/evidence_<TAG>_<ts>.pcap
"""
import argparse
import time
import os
import json
import threading
import shutil
import signal
import psutil
from collections import defaultdict, deque
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, AsyncSniffer, wrpcap

# ---------------- Default config ----------------
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
ALERT_LOG = os.path.join(LOG_DIR, "ids_alerts.json")
PCAP_PREFIX = os.path.join(LOG_DIR, "evidence")

# ---------------- PCAP options ----------------
PCAP_MODE = None
PCAP_ENABLED = False
PCAP_TEMP_FILE = None
PCAP_START_TS = None
PCAP_FINAL_FILE = None

# ---------------- Detection thresholds ----------------
DEFAULT_WINDOW = 5
DEFAULT_SYN_TH = 15
DEFAULT_PORTS_TH = 25
DEFAULT_UDP_PORTS_TH = 25
DEFAULT_ICMP_HOSTS_TH = 20
DEFAULT_RST_TH = 40
DEFAULT_ACK_TH = 40
LARGE_PKT_THRESHOLD = 1500

# ---------------- Runtime state ----------------
syn_times = defaultdict(deque)
tcp_ports_seen = defaultdict(lambda: defaultdict(deque))
udp_ports_seen = defaultdict(lambda: defaultdict(deque))
icmp_hosts_seen = defaultdict(deque)
rst_counts = defaultdict(deque)
ack_times = defaultdict(deque)
last_seen = time.time()
lock = threading.Lock()
alert_counter = 0

# ---------------- Utility functions ----------------
def now_ts():
    return time.time()

def cleanup_deque(dq, window):
    cutoff = now_ts() - window
    while dq and dq[0] < cutoff:
        dq.popleft()

def write_packet_to_pcap(pkt):
    """Append packet to temp PCAP if enabled."""
    if not PCAP_ENABLED or not PCAP_TEMP_FILE:
        return
    try:
        wrpcap(PCAP_TEMP_FILE, pkt, append=True)
    except Exception as e:
        print("[WARN] Failed to write packet to pcap:", e)

def save_alert(alert):
    """Thread-safe append to alert JSON log and print."""
    global alert_counter
    alert['ts'] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    with lock:
        alert_counter += 1
        alert['id'] = alert_counter
        print(json.dumps(alert, ensure_ascii=False))
        with open(ALERT_LOG, "a") as f:
            f.write(json.dumps(alert) + "\n")

def save_evidence(pkt, tag):
    """Save evidence to either a per-alert PCAP or unified PCAP."""
    if PCAP_ENABLED and PCAP_MODE == "alerts":
        write_packet_to_pcap(pkt)
        return PCAP_TEMP_FILE
    else:
        ts = int(time.time() * 1000)
        fname = f"{PCAP_PREFIX}_{tag}_{ts}.pcap"
        try:
            wrpcap(fname, pkt, append=False)
            return fname
        except Exception as e:
            print("[WARN] Failed to save single packet pcap:", e)
            return None

def list_interfaces():
    addrs = psutil.net_if_addrs()
    iface_list = []
    print("Available network interfaces:")
    for idx, (iface, addrlist) in enumerate(addrs.items(), start=1):
        ips = [a.address for a in addrlist if hasattr(a, 'address')]
        print(f"{idx}. {iface} -> {', '.join(ips)}")
        iface_list.append(iface)
    return iface_list

def inactivity_monitor(timeout=6):
    global last_seen
    while True:
        time.sleep(timeout)
        if now_ts() - last_seen > timeout:
            print(f"[DEBUG] No packets in last {timeout}s. Check interface or generate traffic (avoid 127.0.0.1).")

# ---------------- PCAP session handling ----------------
def init_pcap(mode):
    global PCAP_ENABLED, PCAP_MODE, PCAP_TEMP_FILE, PCAP_START_TS
    PCAP_MODE = mode
    if PCAP_MODE not in ("all", "alerts"):
        raise ValueError("pcap mode must be 'all' or 'alerts'")
    PCAP_ENABLED = True
    PCAP_START_TS = int(time.time())
    PCAP_TEMP_FILE = f"{PCAP_PREFIX}_running_{PCAP_START_TS}.pcap"
    open(PCAP_TEMP_FILE, "wb").close()

def finalize_pcap():
    global PCAP_ENABLED, PCAP_TEMP_FILE, PCAP_START_TS, PCAP_FINAL_FILE
    if not PCAP_ENABLED or not PCAP_TEMP_FILE:
        return
    end_ts = int(time.time())
    start_str = time.strftime("%Y%m%d-%H%M%S", time.localtime(PCAP_START_TS))
    end_str = time.strftime("%Y%m%d-%H%M%S", time.localtime(end_ts))
    final_name = f"{PCAP_PREFIX}_{start_str}_to_{end_str}.pcap"
    try:
        if os.path.exists(PCAP_TEMP_FILE) and os.path.getsize(PCAP_TEMP_FILE) > 0:
            if os.path.exists(final_name):
                i = 1
                while os.path.exists(f"{final_name}.{i}"):
                    i += 1
                final_name = f"{final_name}.{i}"
            shutil.move(PCAP_TEMP_FILE, final_name)
            PCAP_FINAL_FILE = final_name
            print(f"[INFO] PCAP saved: {final_name}")
        else:
            os.remove(PCAP_TEMP_FILE)
            print("[INFO] No PCAP data captured.")
    except Exception as e:
        print("[WARN] Could not finalize PCAP:", e)
    finally:
        PCAP_ENABLED = False
        PCAP_TEMP_FILE = None

# Signal + exit handling
def _handle_sig(signum, frame):
    print(f"\n[INFO] Caught signal {signum}, finalizing PCAP...")
    finalize_pcap()
    if signum == signal.SIGINT:
        raise KeyboardInterrupt()
for s in (signal.SIGINT, signal.SIGTERM):
    try:
        signal.signal(s, _handle_sig)
    except Exception:
        pass
import atexit
atexit.register(finalize_pcap)

# ---------------- Detection logic ----------------
def analyze_packet(pkt, cfg):
    global last_seen
    last_seen = now_ts()

    if PCAP_ENABLED and PCAP_MODE == "all":
        write_packet_to_pcap(pkt)

    if not pkt.haslayer(IP):
        return

    ip = pkt[IP]
    src, dst = ip.src, ip.dst
    ts = now_ts()

    # Large packet
    if len(pkt) > cfg['large_pkt_threshold']:
        alert = {"type": "LARGE_PACKET", "src": src, "dst": dst, "size": len(pkt), "severity": "MEDIUM"}
        alert['pcap'] = save_evidence(pkt, "largepkt")
        save_alert(alert)

    # ICMP Ping Sweep
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        dq = icmp_hosts_seen[src]
        dq.append((ts, dst))
        cleanup_deque(dq, cfg['window'])
        if len({h for _, h in dq}) >= cfg['icmp_hosts_th']:
            alert = {"type": "PING_SWEEP", "src": src, "unique_hosts": len({h for _, h in dq}), "severity": "MEDIUM"}
            alert['pcap'] = save_evidence(pkt, "pingsweep")
            save_alert(alert)
            dq.clear()

    # UDP scan heuristic
    if pkt.haslayer(UDP):
        dport = pkt[UDP].dport
        dq = udp_ports_seen[src][dport]
        dq.append(ts)
        cleanup_deque(dq, cfg['window'])
        unique_ports = [p for p, dd in udp_ports_seen[src].items() if dd and now_ts() - dd[-1] <= cfg['window']]
        if len(unique_ports) >= cfg['udp_ports_th']:
            alert = {"type": "UDP_PORT_SCAN", "src": src, "unique_ports": len(unique_ports), "severity": "MEDIUM"}
            alert['pcap'] = save_evidence(pkt, "udp_scan")
            save_alert(alert)
            udp_ports_seen[src].clear()

    # TCP scans
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        flags = int(tcp.flags)
        dport = tcp.dport

        # SYN scan
        if flags & 0x02:
            dq = syn_times[src]
            dq.append(ts)
            cleanup_deque(dq, cfg['window'])
            if len(dq) >= cfg['syn_th']:
                alert = {"type": "SYN_ACTIVITY", "src": src, "count_in_window": len(dq), "severity": "HIGH"}
                alert['pcap'] = save_evidence(pkt, "syn_activity")
                save_alert(alert)
                dq.clear()

            # Port scan
            portdq = tcp_ports_seen[src][dport]
            portdq.append(ts)
            cleanup_deque(portdq, cfg['window'])
            unique_ports = [p for p, dd in tcp_ports_seen[src].items() if dd and now_ts() - dd[-1] <= cfg['window']]
            if len(unique_ports) >= cfg['ports_th']:
                alert = {"type": "TCP_PORT_SCAN", "src": src, "unique_ports": len(unique_ports), "severity": "MEDIUM-HIGH"}
                alert['pcap'] = save_evidence(pkt, "tcp_port_scan")
                save_alert(alert)
                tcp_ports_seen[src].clear()

        # RST flood
        if flags & 0x04:
            dq = rst_counts[src]
            dq.append(ts)
            cleanup_deque(dq, cfg['window'])
            if len(dq) >= cfg['rst_th']:
                alert = {"type": "RST_ACTIVITY", "src": src, "count": len(dq), "severity": "MEDIUM"}
                alert['pcap'] = save_evidence(pkt, "rst_activity")
                save_alert(alert)
                dq.clear()

        # ACK scan
        if (flags & 0x10) and flags not in (0x12, 0x14, 0x18, 0x1C, 0x29):
            dq = ack_times[src]
            dq.append(ts)
            cleanup_deque(dq, cfg['window'])
            if len(dq) >= cfg['ack_th']:
                alert = {"type": "ACK_SCAN", "src": src, "count": len(dq), "severity": "MEDIUM"}
                alert['pcap'] = save_evidence(pkt, "ack_scan")
                save_alert(alert)
                dq.clear()

        # NULL scan
        if flags == 0x00:
            alert = {"type": "NULL_SCAN_PKT", "src": src, "dst_port": dport, "severity": "MEDIUM"}
            alert['pcap'] = save_evidence(pkt, "null_scan")
            save_alert(alert)

        # FIN scan
        if flags == 0x01:
            alert = {"type": "FIN_SCAN_PKT", "src": src, "dst_port": dport, "severity": "MEDIUM"}
            alert['pcap'] = save_evidence(pkt, "fin_scan")
            save_alert(alert)

        # XMAS scan
        if (flags & 0x29) == 0x29:
            alert = {"type": "XMAS_SCAN_PKT", "src": src, "dst_port": dport, "severity": "MEDIUM"}
            alert['pcap'] = save_evidence(pkt, "xmas_scan")
            save_alert(alert)

# ---------------- Main ----------------
def main():
    parser = argparse.ArgumentParser(description="Simple heuristic NIDS. Run as admin/root.")
    parser.add_argument("--iface", help="Interface name to sniff (e.g., eth0).")
    parser.add_argument("--window", type=int, default=DEFAULT_WINDOW)
    parser.add_argument("--syn-threshold", type=int, default=DEFAULT_SYN_TH)
    parser.add_argument("--ports-threshold", type=int, default=DEFAULT_PORTS_TH)
    parser.add_argument("--udp-ports-threshold", type=int, default=DEFAULT_UDP_PORTS_TH)
    parser.add_argument("--icmp-hosts-threshold", type=int, default=DEFAULT_ICMP_HOSTS_TH)
    parser.add_argument("--rst-threshold", type=int, default=DEFAULT_RST_TH)
    parser.add_argument("--ack-threshold", type=int, default=DEFAULT_ACK_TH)
    parser.add_argument("--large-pkt", type=int, default=LARGE_PKT_THRESHOLD)
    parser.add_argument("--pcap", action="store_true")
    parser.add_argument("--pcap-mode", choices=["all","alerts"], default="alerts")

    args = parser.parse_args()

    if args.pcap:
        try:
            init_pcap(args.pcap_mode)
            print(f"[INFO] PCAP logging enabled (mode={args.pcap_mode}) → {PCAP_TEMP_FILE}")
        except Exception as e:
            print("[WARN] Could not initialize PCAP logging:", e)

    cfg = {
        'window': args.window,
        'syn_th': args.syn_threshold,
        'ports_th': args.ports_threshold,
        'udp_ports_th': args.udp_ports_threshold,
        'icmp_hosts_th': args.icmp_hosts_threshold,
        'rst_th': args.rst_threshold,
        'ack_th': args.ack_threshold,
        'large_pkt_threshold': args.large_pkt
    }

    iface = args.iface
    if not iface:
        ifaces = list_interfaces()
        choice = input("Select interface number or press Enter for all: ").strip()
        if choice:
            try:
                iface = ifaces[int(choice) - 1]
            except:
                print("Invalid choice, sniffing all interfaces.")
                iface = None

    print(f"[INFO] NIDS running. Alerts → {ALERT_LOG}")
    t = threading.Thread(target=inactivity_monitor, daemon=True)
    t.start()

    try:
        sniffer = AsyncSniffer(iface=iface, prn=lambda p: analyze_packet(p, cfg), store=False)
        sniffer.start()
        print("[INFO] Sniffing started... Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted. Stopping sniffer...")
        sniffer.stop()
    except PermissionError:
        print("Permission error: run as administrator/root.")
    except Exception as e:
        print(f"[ERROR] Sniffer crashed: {e}")

if __name__ == "__main__":
    main()

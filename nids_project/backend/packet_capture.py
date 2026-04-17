"""
packet_capture.py
- Live mode: raw socket capture (no Scapy IPv6 bug) with Scapy/dpkt fallback
- Simulation: normal traffic only; attacks only on button click
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import time, random, logging, threading, socket, struct
from queue import Queue
from datetime import datetime
from config import Config

logger    = logging.getLogger(__name__)
PROTO_MAP = {1:"ICMP", 6:"TCP", 17:"UDP", 58:"ICMPv6"}
packet_queue: Queue = Queue(maxsize=200)
_stop_event  = threading.Event()
_attack_mode = {"active": False, "type": None}


# ── Packet dict builder ───────────────────────────────────────────────────────
def _build(src, dst, sport, dport, proto, size, flags=0, ttl=64, sim=None):
    p = {
        "timestamp":     datetime.now().isoformat(),
        "src_ip":        str(src),   "dst_ip":        str(dst),
        "src_port":      int(sport), "dst_port":      int(dport),
        "protocol":      PROTO_MAP.get(int(proto), "OTHER"),
        "protocol_num":  int(proto), "packet_length": int(size),
        "flags":         int(flags), "ttl":           int(ttl),
        "bytes":         int(size),  "duration":      0.0,
    }
    if sim: p["_sim_type"] = sim
    return p

def _rand_ip():
    return (f"{random.randint(1,254)}.{random.randint(0,254)}."
            f"{random.randint(0,254)}.{random.randint(1,254)}")


# ── Live capture via raw socket (no Scapy IPv6 dependency) ───────────────────
def _parse_raw(raw: bytes) -> dict | None:
    """Parse raw IP packet bytes → packet dict."""
    try:
        if len(raw) < 20: return None
        ihl    = (raw[0] & 0x0F) * 4
        proto  = raw[9]
        ttl    = raw[8]
        src_ip = socket.inet_ntoa(raw[12:16])
        dst_ip = socket.inet_ntoa(raw[16:20])
        size   = len(raw)
        sport  = dport = flags = 0

        if proto == 6 and len(raw) >= ihl + 20:   # TCP
            tcp    = raw[ihl:]
            sport  = struct.unpack('!H', tcp[0:2])[0]
            dport  = struct.unpack('!H', tcp[2:4])[0]
            flags  = tcp[13] & 0x3F
        elif proto == 17 and len(raw) >= ihl + 8:  # UDP
            udp   = raw[ihl:]
            sport = struct.unpack('!H', udp[0:2])[0]
            dport = struct.unpack('!H', udp[2:4])[0]
        elif proto == 1:                            # ICMP
            pass
        else:
            return None   # skip non-IP protocols

        return _build(src_ip, dst_ip, sport, dport, proto, size, flags, ttl)
    except Exception as e:
        logger.debug(f"parse_raw: {e}")
        return None


def _raw_socket_capture():
    """Capture using raw socket — works without Scapy, requires root/admin."""
    try:
        # ETH_P_IP = 0x0800
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        logger.info("Raw socket capture started (AF_PACKET)")

        # Bind to specific interface if configured
        iface = Config.NETWORK_INTERFACE
        if not iface:
            # Auto-detect: pick first non-loopback interface
            import subprocess
            try:
                out = subprocess.check_output(['ip', 'route', 'get', '8.8.8.8'],
                                              stderr=subprocess.DEVNULL).decode()
                for word in out.split():
                    if word == 'dev':
                        iface = out.split()[out.split().index('dev') + 1]
                        break
            except Exception:
                iface = None

        if iface:
            s.bind((iface, 0))
            logger.info(f"Bound to interface: {iface}")

        s.settimeout(1.0)
        while not _stop_event.is_set():
            try:
                raw, _ = s.recvfrom(65535)
                # Skip Ethernet header (14 bytes) if present
                if len(raw) > 14:
                    pkt = _parse_raw(raw[14:])  # strip Ethernet
                    if pkt is None:
                        pkt = _parse_raw(raw)   # try without stripping
                if pkt and not packet_queue.full():
                    packet_queue.put(pkt)
            except socket.timeout:
                continue
            except Exception as e:
                logger.debug(f"recvfrom: {e}")
        s.close()
    except PermissionError:
        raise
    except Exception as e:
        logger.error(f"Raw socket failed: {e}")
        raise


def _scapy_capture():
    """Scapy capture — fallback, suppress IPv6 errors."""
    import os
    os.environ['SCAPY_USE_LIBPCAP'] = '1'
    # Suppress IPv6 routing errors
    import warnings; warnings.filterwarnings('ignore')

    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.sendrecv import sniff

    def _cb(pkt):
        try:
            if not pkt.haslayer(IP): return
            ip = pkt[IP]
            sport = dport = flags = 0
            if pkt.haslayer(TCP):
                sport = pkt[TCP].sport; dport = pkt[TCP].dport
                flags = int(pkt[TCP].flags)
            elif pkt.haslayer(UDP):
                sport = pkt[UDP].sport; dport = pkt[UDP].dport
            p = _build(ip.src, ip.dst, sport, dport, ip.proto,
                       len(pkt), flags, int(ip.ttl))
            if not packet_queue.full(): packet_queue.put(p)
        except Exception: pass

    iface = Config.NETWORK_INTERFACE
    logger.info(f"Scapy capture on {iface or 'auto'}")
    sniff(iface=iface, filter="ip", prn=_cb, store=False,
          stop_filter=lambda _: _stop_event.is_set())


def start_live_capture() -> threading.Thread:
    """Start live capture. Tries raw socket → Scapy → simulation."""
    def _run():
        # Try 1: raw socket (most reliable, no IPv6 bug)
        try:
            logger.info("Attempting raw socket capture…")
            _raw_socket_capture()
            return
        except PermissionError:
            logger.warning("Raw socket needs root/admin. Try: sudo python run.py --live")
        except Exception as e:
            logger.warning(f"Raw socket failed: {e}")

        # Try 2: Scapy (with IPv6 suppressed)
        try:
            logger.info("Trying Scapy capture…")
            _scapy_capture()
            return
        except ImportError:
            logger.warning("Scapy not installed")
        except Exception as e:
            logger.warning(f"Scapy failed: {e}")

        # Fallback: simulation
        logger.warning("Live capture unavailable — running simulation")
        _run_sim()

    t = threading.Thread(target=_run, daemon=True, name="live-capture")
    t.start()
    return t


# ── Simulation traffic ────────────────────────────────────────────────────────
_NORM_SRC = [
    "192.168.1.10","192.168.1.15","192.168.1.20","192.168.1.25",
    "10.0.0.5","10.0.0.12","10.0.0.20","172.16.0.3",
    "192.168.0.50","10.10.0.5",
]
_NORM_DST = [
    "8.8.8.8","1.1.1.1","93.184.216.34","151.101.1.140",
    "192.168.1.1","10.0.0.1","52.86.54.121","104.16.0.1",
]
_ATK_SRC = [
    "45.33.32.156","198.20.69.74","66.240.192.138",
    "218.92.0.135","103.82.0.1","194.165.16.73",
    "185.220.101.1","91.108.4.0","5.188.206.14","80.82.77.139",
]
_SVCS = [(80,6),(443,6),(53,17),(22,6),(25,6),(3306,6),(8080,6),(21,6),(110,6),(443,6)]

def _sim_normal_packet():
    dport, proto = random.choice(_SVCS)
    return _build(random.choice(_NORM_SRC), random.choice(_NORM_DST),
                  random.randint(1024,65535), dport, proto,
                  random.randint(64, 900),
                  random.choice([0,2,16,18,24]) if proto==6 else 0,
                  random.randint(50,128))

def _sim_dos():
    return _build(random.choice(_ATK_SRC), random.choice(_NORM_DST[:4]),
                  random.randint(1024,65535), 80, 6,
                  random.randint(40,80), 2, 64, "DoS")

def _sim_scan():
    return _build(random.choice(_ATK_SRC), random.choice(_NORM_DST[:3]),
                  random.randint(1024,65535), random.randint(1,65535), 6,
                  44, 2, 45, "PortScan")

def _sim_brute():
    return _build(random.choice(_ATK_SRC), random.choice(_NORM_DST[:4]),
                  random.randint(1024,65535), 22, 6,
                  random.randint(100,300), 24, 64, "BruteForce")

def _sim_ddos():
    return _build(_rand_ip(), random.choice(_NORM_DST[:2]),
                  random.randint(1024,65535), random.choice([7,19,53,80,443]), 17,
                  random.randint(500,1500), 0, random.randint(10,60), "DDoS")

def _sim_botnet():
    return _build(random.choice(_ATK_SRC), _rand_ip(),
                  random.randint(1024,65535), random.choice([6667,1080,4444,8443]),
                  6, random.randint(100,600), 24, 64, "Botnet")

def _sim_web():
    return _build(random.choice(_ATK_SRC), random.choice(_NORM_DST),
                  random.randint(1024,65535), random.choice([80,443,8080]),
                  6, random.randint(800,1500), 24, 64, "WebAttack")

_ATK_FNS = {
    "DoS":_sim_dos, "DDoS":_sim_ddos, "PortScan":_sim_scan,
    "BruteForce":_sim_brute, "Botnet":_sim_botnet, "WebAttack":_sim_web,
}

def trigger_attack(t=None):
    _attack_mode["active"] = True
    _attack_mode["type"]   = t

def stop_attack():
    _attack_mode["active"] = False
    _attack_mode["type"]   = None
    # Drain any buffered attack packets so stop is truly instant
    drained = 0
    while not packet_queue.empty():
        try:
            packet_queue.get_nowait()
            drained += 1
        except Exception:
            break
    if drained:
        logger.info(f"Drained {drained} queued packets on stop")


def _run_sim():
    """Normal traffic only. Attacks ONLY when trigger_attack() called.
    Stop is instant — checked every single packet."""

    while not _stop_event.is_set():
        if _attack_mode["active"]:
            # ── Attack mode: inject attack packets at a steady, visible rate
            atype    = _attack_mode["type"]
            burst_fn = _ATK_FNS.get(atype, random.choice(list(_ATK_FNS.values())))

            # Mix: ~70% attack, ~30% normal for realism
            if random.random() < 0.7:
                pkt = burst_fn()
            else:
                pkt = _sim_normal_packet()

            if not packet_queue.full():
                packet_queue.put(pkt)

            # Steady rate — fast enough to see attacks, slow enough to be smooth
            time.sleep(random.uniform(0.04, 0.08))
        else:
            # ── Normal mode: background traffic
            if not packet_queue.full():
                packet_queue.put(_sim_normal_packet())
            time.sleep(random.uniform(0.07, 0.11))


def start_simulation() -> threading.Thread:
    logger.info("Simulation mode — normal traffic only; attacks via button")
    t = threading.Thread(target=_run_sim, daemon=True, name="sim")
    t.start()
    return t

def stop_capture():
    _stop_event.set()

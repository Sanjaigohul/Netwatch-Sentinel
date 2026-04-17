"""
feature_extractor.py – Extracts 17 network features per packet.
Includes bonus flow-based features (CICFlowMeter-style).
"""
import numpy as np
from collections import defaultdict, deque
import time


class FeatureExtractor:
    """
    Stateful feature extractor.  Maintains sliding windows of per-IP and
    per-flow statistics to compute rate-based and flow-based features.
    """

    N_FEATURES  = 17
    FEATURE_NAMES = [
        "proto_tcp", "proto_udp", "proto_icmp",
        "src_port_norm", "dst_port_norm", "is_wellknown_port",
        "pkt_size_norm", "packet_rate_norm", "byte_rate_norm",
        "flow_duration_norm", "conn_count_norm",
        "size_mean_norm", "size_var_norm",
        "flags_norm", "flow_pkt_count_norm",
        "flow_bytes_norm", "unique_dst_ports_norm",
    ]

    # Normalisation caps
    _MAX_RATE      = 2000.0
    _MAX_BYTE_RATE = 5_000_000.0
    _MAX_DURATION  = 3600.0
    _MAX_CONNS     = 200.0
    _MAX_SIZE      = 65535.0
    _MAX_PORTS     = 65535.0
    _MAX_PKT_CNT   = 50_000.0
    _MAX_BYTES     = 10_000_000.0

    def __init__(self, window_size: int = 10, ip_history: int = 200):
        self.window_size  = window_size
        self.ip_history   = ip_history

        # Per-IP tracking
        self._ip_times: dict[str, deque] = defaultdict(lambda: deque(maxlen=ip_history))
        self._ip_sizes: dict[str, deque] = defaultdict(lambda: deque(maxlen=ip_history))

        # Per-flow stats
        self._flows: dict[str, dict] = defaultdict(lambda: {
            "count": 0, "bytes": 0,
            "start": None, "last": None,
            "sizes": deque(maxlen=200),
        })

        # Sliding feature window (for LSTM)
        self._window: deque = deque(maxlen=window_size)
        self._last_duration: float = 0.0
        self._ip_first_seen: dict = {}  # src_ip -> first timestamp

    # ── Public API ───────────────────────────────────────────────────────────

    def extract(self, pkt: dict) -> np.ndarray:
        """
        pkt must contain keys:
          src_ip, dst_ip, src_port, dst_port,
          protocol_num, packet_length, flags, timestamp
        Returns a float32 ndarray of shape (N_FEATURES,)
        """
        src   = pkt.get("src_ip",       "0.0.0.0")
        dst   = pkt.get("dst_ip",       "0.0.0.0")
        sport = int(pkt.get("src_port", 0))
        dport = int(pkt.get("dst_port", 0))
        proto = int(pkt.get("protocol_num", 0))
        size  = int(pkt.get("packet_length", 0))
        flags = int(pkt.get("flags", 0) or 0)
        _ts_raw = pkt.get("timestamp", time.time())
        try:
            ts = float(_ts_raw)
        except (ValueError, TypeError):
            from datetime import datetime as _dt
            try:
                ts = _dt.fromisoformat(str(_ts_raw)).timestamp()
            except Exception:
                ts = time.time()

        fkey  = f"{src}:{sport}-{dst}:{dport}-{proto}"

        # ── Update flow state ────────────────────────────────────────────────
        fl = self._flows[fkey]
        fl["count"] += 1
        fl["bytes"] += size
        fl["sizes"].append(size)
        if fl["start"] is None:
            fl["start"] = ts
        fl["last"] = ts
        fl["duration"] = fl["last"] - fl["start"]

        # ── Update IP state ──────────────────────────────────────────────────
        self._ip_times[src].append(ts)
        self._ip_sizes[src].append(size)

        # ── Feature computation ──────────────────────────────────────────────
        # 1-3  Protocol one-hot
        p_tcp  = float(proto == 6)
        p_udp  = float(proto == 17)
        p_icmp = float(proto == 1)

        # 4-6  Port features
        sp_n = min(sport / self._MAX_PORTS, 1.0)
        dp_n = min(dport / self._MAX_PORTS, 1.0)
        well_known = float(sport < 1024 or dport < 1024)

        # 7    Packet size
        pkt_size_n = min(size / self._MAX_SIZE, 1.0)

        # 8    Packet rate from src_ip
        itimes = list(self._ip_times[src])
        if len(itimes) > 1:
            span = itimes[-1] - itimes[0]
            pkt_rate = len(itimes) / span if span > 0 else len(itimes)
        else:
            pkt_rate = 1.0
        pkt_rate_n = min(pkt_rate / self._MAX_RATE, 1.0)

        # 9    Byte rate from src_ip
        isizes = list(self._ip_sizes[src])
        if len(itimes) > 1 and (itimes[-1] - itimes[0]) > 0:
            byte_rate = sum(isizes) / (itimes[-1] - itimes[0])
        else:
            byte_rate = float(size)
        byte_rate_n = min(byte_rate / self._MAX_BYTE_RATE, 1.0)

        # 10   Flow duration
        fl_dur = (fl["last"] - fl["start"]) if fl["start"] else 0.0
        fl_dur_n = min(fl_dur / self._MAX_DURATION, 1.0)

        # 11   Unique active connections from src
        conn_cnt = sum(1 for k in self._flows if k.startswith(src + ":"))
        conn_n   = min(conn_cnt / self._MAX_CONNS, 1.0)

        # 12-13 Statistical size features within flow
        fsizes = list(fl["sizes"])
        if len(fsizes) > 1:
            sz_mean = np.mean(fsizes) / self._MAX_SIZE
            sz_var  = min(np.var(fsizes) / (self._MAX_SIZE ** 2), 1.0)
        else:
            sz_mean = pkt_size_n
            sz_var  = 0.0

        # 14   TCP flags
        flags_n = min(flags / 64.0, 1.0)

        # 15   Flow packet count
        fl_cnt_n = min(fl["count"] / self._MAX_PKT_CNT, 1.0)

        # 16   Flow byte total
        fl_bytes_n = min(fl["bytes"] / self._MAX_BYTES, 1.0)

        # 17   Unique destination ports from src (port-scan indicator)
        unique_dsts = len({k.split("-")[1].split(":")[1]
                           for k in self._flows if k.startswith(src + ":")})
        udst_n = min(unique_dsts / self._MAX_PORTS, 1.0)

        fvec = np.array([
            p_tcp, p_udp, p_icmp,
            sp_n, dp_n, well_known,
            pkt_size_n,
            pkt_rate_n, byte_rate_n,
            fl_dur_n, conn_n,
            float(sz_mean), float(sz_var),
            flags_n,
            fl_cnt_n, fl_bytes_n,
            udst_n,
        ], dtype=np.float32)

        # Update LSTM window
        # Duration: time since this src_ip was first seen
        if src not in self._ip_first_seen:
            self._ip_first_seen[src] = ts
        self._last_duration = float(ts - self._ip_first_seen[src])
        self._window.append(fvec)
        return fvec

    def get_window(self, fvec: np.ndarray) -> np.ndarray:
        """
        Returns the current sliding window of shape (window_size, N_FEATURES).
        Pads with zeros if fewer than window_size packets have been seen.
        """
        if len(self._window) >= self.window_size:
            return np.array(list(self._window), dtype=np.float32)
        padded = np.zeros((self.window_size, self.N_FEATURES), dtype=np.float32)
        current = list(self._window)
        padded[-len(current):] = current
        return padded

    @property
    def last_duration(self) -> float:
        return getattr(self, '_last_duration', 0.0)

    def reset(self):
        """Clear all state (useful between test runs)."""
        self._ip_times.clear()
        self._ip_sizes.clear()
        self._flows.clear()
        self._window.clear()

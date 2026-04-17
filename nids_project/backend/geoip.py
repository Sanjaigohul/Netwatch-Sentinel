"""
backend/geoip.py
Free IP geolocation using ip-api.com (no API key needed).
Caches results in memory. Private/loopback IPs return local info.
"""
import logging
import threading
import requests
from functools import lru_cache

logger = logging.getLogger(__name__)

# Private IP ranges — never look these up
_PRIVATE_PREFIXES = (
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "0.", "169.254.", "::1", "fc", "fd",
)

_UNKNOWN = {"country": "—", "country_code": "", "isp": "—", "city": "—"}
_LOCAL   = {"country": "Local", "country_code": "LO", "isp": "Private Network", "city": "—"}
_cache: dict = {}
_lock  = threading.Lock()

# Country code → flag emoji
_FLAGS = {
    "US":"🇺🇸","GB":"🇬🇧","DE":"🇩🇪","CN":"🇨🇳","RU":"🇷🇺",
    "IN":"🇮🇳","FR":"🇫🇷","JP":"🇯🇵","KR":"🇰🇷","BR":"🇧🇷",
    "AU":"🇦🇺","CA":"🇨🇦","NL":"🇳🇱","SG":"🇸🇬","SE":"🇸🇪",
    "NO":"🇳🇴","FI":"🇫🇮","CH":"🇨🇭","IT":"🇮🇹","ES":"🇪🇸",
    "PL":"🇵🇱","UA":"🇺🇦","TR":"🇹🇷","MX":"🇲🇽","AR":"🇦🇷",
    "ZA":"🇿🇦","NG":"🇳🇬","EG":"🇪🇬","PK":"🇵🇰","BD":"🇧🇩",
    "LO":"🏠",
}


def is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def lookup(ip: str) -> dict:
    """Return {country, country_code, isp, city, flag} for an IP."""
    if not ip or ip in ("0.0.0.0", ""):
        return {**_UNKNOWN, "flag": "🌐"}

    if is_private(ip):
        return {**_LOCAL, "flag": "🏠"}

    with _lock:
        if ip in _cache:
            return _cache[ip]

    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,city,isp,org"},
            timeout=3,
        )
        data = r.json()
        if data.get("status") == "success":
            cc   = data.get("countryCode", "")
            info = {
                "country":      data.get("country", "—"),
                "country_code": cc,
                "city":         data.get("city", "—"),
                "isp":          data.get("isp") or data.get("org") or "—",
                "flag":         _FLAGS.get(cc, "🌐"),
            }
        else:
            info = {**_UNKNOWN, "flag": "🌐"}
    except Exception as e:
        logger.debug(f"GeoIP lookup {ip}: {e}")
        info = {**_UNKNOWN, "flag": "🌐"}

    with _lock:
        _cache[ip] = info
        # Cap cache size
        if len(_cache) > 5000:
            oldest = list(_cache.keys())[:500]
            for k in oldest:
                del _cache[k]

    return info


def lookup_async(ip: str, callback) -> None:
    """Non-blocking lookup — calls callback(ip, info) when done."""
    def _run():
        info = lookup(ip)
        try: callback(ip, info)
        except Exception: pass
    threading.Thread(target=_run, daemon=True).start()


def batch_lookup(ips: list[str]) -> dict[str, dict]:
    """Look up multiple IPs, returns {ip: info} dict."""
    result = {}
    threads = []
    lock = threading.Lock()

    def _fetch(ip):
        info = lookup(ip)
        with lock:
            result[ip] = info

    for ip in set(ips):
        t = threading.Thread(target=_fetch, args=(ip,), daemon=True)
        threads.append(t); t.start()
    for t in threads:
        t.join(timeout=4)

    return result

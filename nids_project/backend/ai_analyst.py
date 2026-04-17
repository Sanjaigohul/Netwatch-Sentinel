"""
backend/ai_analyst.py
Qwen AI-powered alert analysis.
Uses OpenRouter API (qwen/qwen2.5-coder-32b-instruct).
Falls back to rule-based explanation when key not configured.
"""
import logging
import requests
from config import Config

logger = logging.getLogger(__name__)


# ── Rule-based fallback descriptions ─────────────────────────────────────────
_RULE_DESCRIPTIONS = {
    "DoS": {
        "title": "Denial of Service Attack",
        "what":  "A single source is flooding the target with TCP SYN packets, exhausting server connection resources.",
        "risk":  "High — can take services offline within seconds if sustained.",
        "action": "1. Block source IP immediately.\n2. Enable SYN cookies on the target server.\n3. Contact upstream provider for traffic filtering.",
    },
    "DDoS": {
        "title": "Distributed Denial of Service Attack",
        "what":  "Multiple IP addresses are sending high-volume UDP traffic to overwhelm bandwidth and exhaust server resources.",
        "risk":  "Critical — distributed nature makes source blocking ineffective.",
        "action": "1. Enable rate limiting at router/firewall level.\n2. Contact ISP for upstream null-route.\n3. Consider CDN / DDoS mitigation service.",
    },
    "PortScan": {
        "title": "Port Scanning / Network Reconnaissance",
        "what":  "An attacker is systematically probing ports across your network to identify open services and vulnerabilities.",
        "risk":  "Medium — reconnaissance often precedes targeted attacks.",
        "action": "1. Block scanner IP.\n2. Review which ports are exposed.\n3. Enable port scan detection in firewall.",
    },
    "BruteForce": {
        "title": "Brute Force Login Attack",
        "what":  "Repeated authentication attempts against SSH (port 22), likely using a dictionary or credential-stuffing attack.",
        "risk":  "High — may result in unauthorized access if weak credentials exist.",
        "action": "1. Block attacker IP immediately.\n2. Enforce key-based SSH authentication.\n3. Install fail2ban or equivalent.",
    },
    "Botnet": {
        "title": "Botnet Command & Control Traffic",
        "what":  "Traffic patterns match known botnet C&C communication (IRC ports, P2P patterns). Host may be infected.",
        "risk":  "Critical — infected hosts can exfiltrate data and attack others.",
        "action": "1. Isolate affected machine from network.\n2. Run full malware scan.\n3. Check for persistence mechanisms.",
    },
    "WebAttack": {
        "title": "Web Application Attack",
        "what":  "Oversized HTTP POST requests targeting web application endpoints — consistent with SQL injection or XSS payloads.",
        "risk":  "High — may lead to data breach or remote code execution.",
        "action": "1. Enable WAF rules.\n2. Review application logs for injection strings.\n3. Patch vulnerable endpoints.",
    },
}


def _rule_analysis(attack_type: str, src_ip: str, dst_ip: str,
                   score: float, threat: str) -> dict:
    """Fast rule-based analysis — no API call."""
    info = _RULE_DESCRIPTIONS.get(attack_type, {
        "title":  f"Unknown Attack: {attack_type}",
        "what":   "Anomalous traffic detected with unusual packet patterns.",
        "risk":   "Unknown — investigate manually.",
        "action": "1. Review packet logs.\n2. Block source IP if suspicious.\n3. Monitor for escalation.",
    })
    return {
        "source":      "rule-based",
        "title":       info["title"],
        "what":        info["what"],
        "risk":        f"{threat} — Anomaly score: {score:.3f}",
        "action":      info["action"],
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "attack_type": attack_type,
    }


def _qwen_analysis(attack_type: str, src_ip: str, dst_ip: str,
                   score: float, threat: str, extra: dict) -> dict:
    """Call Qwen via OpenRouter for AI-powered analysis."""
    prompt = f"""You are a cybersecurity analyst. Analyze this network intrusion alert and provide a brief, actionable response.

Alert Details:
- Attack Type: {attack_type}
- Source IP: {src_ip}
- Destination IP: {dst_ip}
- Anomaly Score: {score:.4f}
- Threat Level: {threat}
- Protocol: {extra.get('protocol', 'Unknown')}
- Packet Size: {extra.get('packet_length', 0)} bytes
- Country: {extra.get('country', 'Unknown')}
- ISP: {extra.get('isp', 'Unknown')}

Respond in this exact JSON format:
{{
  "title": "short attack title",
  "what": "1-2 sentences: what is happening technically",
  "risk": "1 sentence: business/security risk",
  "action": "3 numbered steps the analyst should take right now"
}}"""

    try:
        headers = {
            "Authorization": f"Bearer {Config.QWEN_API_KEY}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://nids-sentinel.local",
        }
        payload = {
            "model": Config.QWEN_MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 400,
            "temperature": 0.3,
        }
        resp = requests.post(
            f"{Config.QWEN_BASE_URL}/chat/completions",
            headers=headers, json=payload, timeout=10,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]

        # Parse JSON from response
        import json, re
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group())
            return {
                "source":      "qwen-ai",
                "title":       data.get("title", f"{attack_type} Attack"),
                "what":        data.get("what",  ""),
                "risk":        data.get("risk",  ""),
                "action":      data.get("action",""),
                "src_ip":      src_ip,
                "dst_ip":      dst_ip,
                "attack_type": attack_type,
            }
    except Exception as e:
        logger.warning(f"Qwen API error: {e} — using rule-based fallback")

    return _rule_analysis(attack_type, src_ip, dst_ip, score, threat)


def analyze_alert(attack_type: str, src_ip: str, dst_ip: str,
                  score: float, threat: str, extra: dict = None) -> dict:
    """
    Analyze an alert. Uses Qwen AI if API key is configured, else rule-based.
    Returns dict with: source, title, what, risk, action, src_ip, dst_ip, attack_type
    """
    if Config.QWEN_API_KEY and Config.QWEN_API_KEY not in ("", "your_qwen_api_key_here"):
        return _qwen_analysis(attack_type, src_ip, dst_ip, score, threat, extra or {})
    return _rule_analysis(attack_type, src_ip, dst_ip, score, threat)

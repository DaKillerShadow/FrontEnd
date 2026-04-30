#import re
from urllib.parse import urlparse

class RuleEngine:
    """Applies deterministic heuristic rules to a URL."""

    # ── Constants ──────────────────────────────────────────────────────────────
    LENGTH_MEDIUM_THRESHOLD = 54
    LENGTH_HIGH_THRESHOLD   = 75
    SUBDOMAIN_THRESHOLD = 3

    SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz",
                       ".top", ".click", ".link", ".win", ".download"}

    SHORTENER_DOMAINS = {
        "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
        "is.gd", "buff.ly", "adf.ly", "shorte.st",
    }

    # ── Compiled Regular Expressions ──────────────────────────────────────────
    _RE_IP_HOST = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$")
    _RE_AT_SIGN = re.compile(r"@")
    _RE_DOUBLE_SLASH = re.compile(r"(?<!:)//")
    _RE_MULTI_HYPHEN = re.compile(r"-{2,}")
    _RE_PERCENT_ENC = re.compile(r"%[0-9a-fA-F]{2}")
    
    # NEW: Detects Punycode prefix (Homograph attacks)
    _RE_PUNYCODE = re.compile(r"^xn--")

    def analyze(self, url: str) -> dict:
        triggered = []
        parsed    = urlparse(url)
        netloc    = parsed.netloc.lower()
        hostname  = netloc.split(":")[0]
        
        clean_host = hostname[4:] if hostname.startswith("www.") else hostname

        # ── New Rule: Punycode / Homograph Detection ─────────────────────────
        if self._RE_PUNYCODE.match(clean_host):
            triggered.append({
                "name": "Punycode (Homograph Attack) Detected",
                "description": (
                    f"The domain '{hostname}' uses Punycode (starts with 'xn--'). "
                    "This is a common technique for homograph attacks where "
                    "international characters are used to visually mimic trusted brands."
                ),
                "severity": "high",
            })

        # ── Rule 1: IP address used as host ───────────────────────────────────
        if self._RE_IP_HOST.match(netloc):
            triggered.append({
                "name": "IP Address as Host",
                "description": f"The URL uses a raw IP address ({netloc}) instead of a domain.",
                "severity": "high",
            })

        # ── Rule 2: URL length ─────────────────────────────────────────────────
        url_len = len(url)
        if url_len > self.LENGTH_HIGH_THRESHOLD:
            triggered.append({
                "name": "Excessively Long URL",
                "description": f"URL length is {url_len} characters. Used to hide malicious domains.",
                "severity": "high",
            })
        elif url_len > self.LENGTH_MEDIUM_THRESHOLD:
            triggered.append({
                "name": "Unusually Long URL",
                "description": f"URL length is {url_len} characters. Slightly above normal.",
                "severity": "medium",
            })

        # ── Rule 3: Excessive subdomains ──────────────────────────────────────
        parts = clean_host.split(".")
        if len(parts) > self.SUBDOMAIN_THRESHOLD:
            triggered.append({
                "name": "Excessive Subdomains",
                "description": f"Hostname has {len(parts)} labels. Brand names may be embedded as subdomains.",
                "severity": "high",
            })

        # ── Rule 4: @ symbol ──────────────────────────────────────────────────
        if self._RE_AT_SIGN.search(url):
            triggered.append({
                "name": "@ Symbol in URL",
                "description": "Browsers discard everything BEFORE '@', redirecting to the host after it.",
                "severity": "high",
            })

        # ── Rule 5: Double slash in path ──────────────────────────────────────
        url_after_scheme = url.split("://", 1)[-1]
        if self._RE_DOUBLE_SLASH.search(url_after_scheme):
            triggered.append({
                "name": "Double Slash Redirection",
                "description": "Found '//' outside the scheme. Can enable open redirect attacks.",
                "severity": "high",
            })

        # ── Rule 6: Multiple hyphens in hostname ──────────────────────────────
        if self._RE_MULTI_HYPHEN.search(hostname):
            triggered.append({
                "name": "Multiple Hyphens in Domain",
                "description": f"Domain '{hostname}' contains consecutive hyphens (common in typosquatting).",
                "severity": "medium",
            })

        # ── Rule 7: HTTP (no TLS) ─────────────────────────────────────────────
        if parsed.scheme == "http":
            triggered.append({
                "name": "No HTTPS (Unencrypted)",
                "description": "Connection is unencrypted; site lacks an SSL certificate.",
                "severity": "medium",
            })

        # ── Rule 8: Suspicious TLD ────────────────────────────────────────────
        for tld in self.SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                triggered.append({
                    "name": "Suspicious Top-Level Domain",
                    "description": f"Domain ends with '{tld}', a TLD frequently used in phishing.",
                    "severity": "high",
                })
                break

        # ── Rule 9: URL shortener ─────────────────────────────────────────────
        for shortener in self.SHORTENER_DOMAINS:
            if clean_host == shortener or clean_host.endswith("." + shortener):
                triggered.append({
                    "name": "URL Shortener Detected",
                    "description": f"Service '{shortener}' masks the true destination.",
                    "severity": "medium",
                })
                break

        # ── Rule 10: Percent-encoded obfuscation ──────────────────────────────
        encoded_count = len(self._RE_PERCENT_ENC.findall(url))
        if encoded_count >= 3:
            triggered.append({
                "name": "Excessive Percent-Encoding",
                "description": f"Found {encoded_count} percent-encoded characters used for obfuscation.",
                "severity": "medium",
            })

        # ── Compute risk score ────────────────────────────────────────────────
        # Note: High severity rules now carry significant weight to avoid false negatives.
        risk_score = sum(
            5 if r["name"] == "Punycode (Homograph Attack) Detected" else 
            (3 if r["severity"] == "high" else 1)
            for r in triggered
        )

        # ── Assign verdict ────────────────────────────────────────────────────
        if risk_score >= 6:
            verdict = "likely_phishing"
        elif risk_score >= 2:
            verdict = "suspicious"
        else:
            verdict = "safe"

        return {
            "triggered_rules": triggered,
            "risk_score": risk_score,
            "verdict": verdict,
        }
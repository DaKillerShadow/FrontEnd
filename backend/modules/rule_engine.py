# =============================================================================
# modules/rule_engine.py  —  RuleEngine (Heuristics / Pattern Matching)
# =============================================================================
# PURPOSE:
#   This is the SECOND layer.  Before invoking the (heavier) ML model we run a
#   lightweight set of deterministic rules based on well-known phishing
#   indicators.  Each rule:
#     • Is implemented with a targeted Regular Expression or simple arithmetic.
#     • Assigns a SEVERITY: "high" (strong indicator) or "medium" (weak/ambiguous).
#     • Produces a human-readable description so the UI can explain *why* a URL
#       was flagged.
#
# WHY THESE RULES?
#   Academic research (e.g. Mohammad et al., 2015) consistently identifies the
#   following as the strongest lexical signals of phishing URLs:
#
#   1.  IP-as-host        – Legitimate services almost always use a domain name.
#                          Phishers use raw IPs to avoid purchasing/registering
#                          a convincing domain.
#
#   2.  URL length        – Phishers hide the real destination inside a very
#                          long string so the malicious part is off-screen in
#                          the browser address bar.
#
#   3.  Subdomain depth   – "secure.login.update.bank.com.evil.ru" is a classic
#                          trick: the *real* domain (evil.ru) is buried at the
#                          right end, while brand names appear as subdomains.
#
#   4.  @ symbol          – RFC 3986 allows an "@" in a URL to separate optional
#                          user-info from the host.  Browsers IGNORE everything
#                          before the @.  So "http://paypal.com@evil.com" takes
#                          you to evil.com.
#
#   5.  Double slash //   – An unexpected // in the path tricks the browser into
#                          treating the next segment as a new authority (host).
#
#   6.  Dash in domain    – A single dash is normal (e.g. amazon-uk.com), but
#                          multiple dashes suggest typosquatting or obfuscation.
#
#   7.  HTTP (no TLS)     – Not proof of phishing alone, but combined with other
#                          signals it strongly increases risk.
#
#   8.  Suspicious TLDs   – Certain free/cheap TLDs (.tk, .ml, .ga, .cf, .gq)
#                          are disproportionately used in phishing campaigns.
#
#   9.  URL shorteners    – bit.ly, tinyurl, etc. hide the true destination.
#
#   10. Hex / percent-    – Encoding characters like "/" as "%2F" is sometimes
#       encoding abuse      used to obfuscate the real path.
# =============================================================================

import re
from urllib.parse import urlparse


class RuleEngine:
    """Applies deterministic heuristic rules to a URL."""

    # ── Constants ──────────────────────────────────────────────────────────────
    # URL length thresholds (characters).  Industry consensus:
    #   < 54  → short / normal
    #   54–75 → moderate suspicion
    #   > 75  → high suspicion
    LENGTH_MEDIUM_THRESHOLD = 54
    LENGTH_HIGH_THRESHOLD   = 75

    # More than this many dot-separated labels in the hostname signals deep
    # subdomain nesting.  "www.paypal.com" has 3 parts → normal.
    SUBDOMAIN_THRESHOLD = 3

    # TLDs commonly abused in phishing (Freenom free domains + others).
    SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz",
                       ".top", ".click", ".link", ".win", ".download"}

    # Well-known URL-shortening services.
    SHORTENER_DOMAINS = {
        "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
        "is.gd", "buff.ly", "adf.ly", "shorte.st",
    }

    # ── Compiled Regular Expressions ──────────────────────────────────────────
    # Compiled once at class level for efficiency (avoids re-compiling on every
    # call to analyze()).

    # Matches a bare IPv4 address in the netloc, e.g. "192.168.1.1" or
    # "192.168.1.1:8080".  The negative lookahead (?!\d) prevents partial matches.
    _RE_IP_HOST = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$"
    )

    # Detects the @ character ANYWHERE in the URL.
    _RE_AT_SIGN = re.compile(r"@")

    # Detects a double-slash that is NOT immediately after the scheme colon,
    # i.e. "http://host//path" or "http://host/path//redirect".
    _RE_DOUBLE_SLASH = re.compile(r"(?<!:)//")

    # Flags domains with 3 or more consecutive hyphens — typosquatting signal.
    _RE_MULTI_HYPHEN = re.compile(r"-{2,}")

    # Detects percent-encoded characters (e.g. %2F, %40) in the path/query.
    _RE_PERCENT_ENC = re.compile(r"%[0-9a-fA-F]{2}")

    # ── Public API ─────────────────────────────────────────────────────────────

    def analyze(self, url: str) -> dict:
        """
        Runs all heuristic rules against *url*.

        Parameters
        ----------
        url : str   Normalised URL (already validated by URLValidator).

        Returns
        -------
        dict with keys:
            triggered_rules  list[dict]  – Each item is one triggered rule.
                                           Keys: name, description, severity.
            risk_score       int         – Sum of severity weights.
            verdict          str         – "safe" | "suspicious" | "likely_phishing"
        """

        triggered = []   # will collect all rule hits
        parsed    = urlparse(url)
        netloc    = parsed.netloc.lower()   # hostname (and optional port)
        hostname  = netloc.split(":")[0]    # strip port if present
        path      = parsed.path
        query     = parsed.query

        # Remove "www." prefix so subdomain counting isn't distorted.
        # BUG FIX (Bug 1): .lstrip("www.") strips CHARACTERS not a substring.
        # For example, "www.western.com".lstrip("www.") returns "estern.com"
        # because 'w' and '.' are both in the character set {"w", "."}.
        # Using hostname[4:] slices exactly 4 characters — safe because we
        # already confirmed the string starts with the literal "www." prefix.
        clean_host = hostname[4:] if hostname.startswith("www.") else hostname

        # ── Rule 1: IP address used as host ───────────────────────────────────
        if self._RE_IP_HOST.match(netloc):
            triggered.append({
                "name": "IP Address as Host",
                "description": (
                    f"The URL uses a raw IP address ({netloc}) instead of a domain "
                    "name.  Legitimate websites almost always use registered domain "
                    "names.  Phishers use IPs to avoid domain registration."
                ),
                "severity": "high",
            })

        # ── Rule 2: URL length ─────────────────────────────────────────────────
        url_len = len(url)
        if url_len > self.LENGTH_HIGH_THRESHOLD:
            triggered.append({
                "name": "Excessively Long URL",
                "description": (
                    f"URL length is {url_len} characters (threshold: "
                    f"{self.LENGTH_HIGH_THRESHOLD}).  Long URLs are used to hide "
                    "the real malicious domain at the end of the string."
                ),
                "severity": "high",
            })
        elif url_len > self.LENGTH_MEDIUM_THRESHOLD:
            triggered.append({
                "name": "Unusually Long URL",
                "description": (
                    f"URL length is {url_len} characters (threshold: "
                    f"{self.LENGTH_MEDIUM_THRESHOLD}).  Slightly above normal — "
                    "worth further inspection."
                ),
                "severity": "medium",
            })

        # ── Rule 3: Excessive subdomains ──────────────────────────────────────
        # Count dot-separated labels in the hostname.
        # "www.paypal.com" → 3 parts → OK
        # "login.secure.update.paypal.com.attacker.ru" → 7 parts → suspicious
        parts = clean_host.split(".")
        if len(parts) > self.SUBDOMAIN_THRESHOLD:
            triggered.append({
                "name": "Excessive Subdomains",
                "description": (
                    f"The hostname has {len(parts)} labels (e.g. "
                    f"'{clean_host}').  Deep subdomain nesting is used to embed "
                    "trusted brand names (e.g. 'paypal') as subdomains while the "
                    "real domain is different."
                ),
                "severity": "high",
            })

        # ── Rule 4: @ symbol ──────────────────────────────────────────────────
        if self._RE_AT_SIGN.search(url):
            triggered.append({
                "name": "@ Symbol in URL",
                "description": (
                    "The URL contains an '@' character.  Browsers discard "
                    "everything BEFORE '@', so 'http://trusted.com@evil.com' "
                    "silently redirects to evil.com."
                ),
                "severity": "high",
            })

        # ── Rule 5: Double slash in path ──────────────────────────────────────
        # We check the full URL but skip the "://" that is expected after scheme.
        url_after_scheme = url.split("://", 1)[-1]
        if self._RE_DOUBLE_SLASH.search(url_after_scheme):
            triggered.append({
                "name": "Double Slash Redirection",
                "description": (
                    "The URL contains '//' outside the expected '://' location.  "
                    "This can trick parsers into treating the segment after '//' "
                    "as a new host, enabling open redirect attacks."
                ),
                "severity": "high",
            })

        # ── Rule 6: Multiple hyphens in hostname ──────────────────────────────
        if self._RE_MULTI_HYPHEN.search(hostname):
            triggered.append({
                "name": "Multiple Hyphens in Domain",
                "description": (
                    f"The domain '{hostname}' contains consecutive hyphens.  "
                    "Phishing domains often use hyphens to mimic legitimate brands "
                    "(e.g. 'pay-pal-secure-login.com')."
                ),
                "severity": "medium",
            })

        # ── Rule 7: HTTP (no TLS) ─────────────────────────────────────────────
        if parsed.scheme == "http":
            triggered.append({
                "name": "No HTTPS (Unencrypted)",
                "description": (
                    "The URL uses plain HTTP instead of HTTPS.  While not proof "
                    "of phishing on its own, the absence of TLS means the "
                    "connection is unencrypted and the site has no SSL certificate."
                ),
                "severity": "medium",
            })

        # ── Rule 8: Suspicious TLD ────────────────────────────────────────────
        for tld in self.SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                triggered.append({
                    "name": "Suspicious Top-Level Domain",
                    "description": (
                        f"The domain ends with '{tld}', a TLD that is "
                        "disproportionately used in phishing campaigns due to its "
                        "low cost or free registration."
                    ),
                    "severity": "high",
                })
                break  # one TLD rule hit is enough

        # ── Rule 9: URL shortener ─────────────────────────────────────────────
        # BUG FIX (Bug 4): Use clean_host (www.-stripped) instead of hostname
        # for consistency. Both variables would catch "www.bit.ly" via
        # .endswith(), but clean_host is the canonically normalised value used
        # everywhere else in this method, so we use it here too for clarity.
        for shortener in self.SHORTENER_DOMAINS:
            if clean_host == shortener or clean_host.endswith("." + shortener):
                triggered.append({
                    "name": "URL Shortener Detected",
                    "description": (
                        f"The URL uses the shortening service '{shortener}'.  "
                        "Shortened URLs completely mask the true destination, "
                        "making it impossible to judge safety by appearance alone."
                    ),
                    "severity": "medium",
                })
                break

        # ── Rule 10: Percent-encoded obfuscation ──────────────────────────────
        encoded_count = len(self._RE_PERCENT_ENC.findall(url))
        if encoded_count >= 3:
            triggered.append({
                "name": "Excessive Percent-Encoding",
                "description": (
                    f"Found {encoded_count} percent-encoded characters (e.g. "
                    "%2F, %40).  A high count can indicate deliberate obfuscation "
                    "to hide the real path or bypass simple text-based filters."
                ),
                "severity": "medium",
            })

        # ── Compute risk score ────────────────────────────────────────────────
        # Simple weighted sum: high=3 points, medium=1 point.
        risk_score = sum(
            3 if r["severity"] == "high" else 1
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

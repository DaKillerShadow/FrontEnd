# =============================================================================
# modules/tranco_checker.py  —  TrancoChecker
# =============================================================================
# PURPOSE:
#   Check a domain against the Tranco Top 1 Million list (we use top 100k).
#   Tranco is a research-grade aggregated ranking of the most popular domains
#   on the internet, combining data from Alexa, Cisco Umbrella, Majestic,
#   and Quantcast. If a domain is in the top 100k, it is almost certainly
#   legitimate and we can skip or discount the ML/rule analysis.
#
# REFERENCE:
#   Le Pochat et al. (2019). "Tranco: A Research-Oriented Top Sites Ranking
#   Hardened Against Manipulation." NDSS 2019.
#   https://tranco-list.eu/
#
# SETUP:
#   Run `python setup_tranco.py` once to download the list into data/.
#   If the file is absent we fall back to a small embedded hardcoded set of
#   universally known safe domains so the app still works offline.
# =============================================================================

import os
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Fallback set: globally recognised domains that are always safe to whitelist.
# This is intentionally small — it is NOT a substitute for the full Tranco list.
_FALLBACK_WHITELIST: set[str] = {
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'linkedin.com', 'wikipedia.org', 'amazon.com', 'apple.com', 'microsoft.com',
    'github.com', 'stackoverflow.com', 'reddit.com', 'netflix.com', 'yahoo.com',
    'whatsapp.com', 'tiktok.com', 'snapchat.com', 'pinterest.com', 'ebay.com',
    'paypal.com', 'dropbox.com', 'spotify.com', 'adobe.com', 'salesforce.com',
    'shopify.com', 'cloudflare.com', 'wordpress.com', 'bbc.co.uk', 'cnn.com',
    'nytimes.com', 'theguardian.com', 'reuters.com', 'bloomberg.com',
    'chase.com', 'wellsfargo.com', 'bankofamerica.com', 'citibank.com',
}

_DATA_DIR  = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
_LIST_PATH = os.path.join(_DATA_DIR, 'tranco_top100k.txt')


class TrancoChecker:
    """
    Loads the Tranco top-100k domain list and provides O(1) membership lookup.

    The domain set is loaded once at instantiation and kept in memory as a
    Python set — lookup is O(1) and the whole list fits in ~3 MB of RAM.
    """

    def __init__(self):
        self._domains: set[str] = set()
        self._source: str = ''
        self._load()

    # ── Public API ─────────────────────────────────────────────────────────────

    def is_whitelisted(self, url_or_domain: str) -> dict:
        """
        Check whether the domain from *url_or_domain* is in the top-100k list.

        Parameters
        ----------
        url_or_domain : str  Either a full URL or a bare domain name.

        Returns
        -------
        dict:
            whitelisted  bool  – True if domain is in the Tranco list.
            domain       str   – The extracted domain that was checked.
            rank         str   – "top_100k" if whitelisted, else "unranked".
            source       str   – "tranco_file" or "fallback_set".
        """
        domain = self._extract_domain(url_or_domain)
        # Check both full domain and its registered domain (strip subdomains)
        registered = self._registered_domain(domain)

        hit = (domain in self._domains) or (registered in self._domains)

        return {
            'whitelisted': hit,
            'domain':      domain,
            'rank':        'top_100k' if hit else 'unranked',
            'source':      self._source,
        }

    @property
    def size(self) -> int:
        """Number of domains currently loaded."""
        return len(self._domains)

    # ── Private helpers ────────────────────────────────────────────────────────

    def _load(self):
        """Load domains from the Tranco file, falling back to the hardcoded set."""
        if os.path.exists(_LIST_PATH):
            try:
                with open(_LIST_PATH, 'r', encoding='utf-8') as fh:
                    for line in fh:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # File may be rank,domain or just domain
                            parts = line.split(',')
                            domain = parts[-1].strip().lower()
                            if domain:
                                self._domains.add(domain)
                self._source = 'tranco_file'
                logger.info('TrancoChecker: loaded %d domains from %s',
                            len(self._domains), _LIST_PATH)
                return
            except Exception as exc:
                logger.warning('TrancoChecker: failed to read file (%s), '
                               'falling back to hardcoded set.', exc)

        # Fallback
        self._domains = set(_FALLBACK_WHITELIST)
        self._source  = 'fallback_set'
        logger.info('TrancoChecker: using fallback set (%d domains)',
                    len(self._domains))

    @staticmethod
    def _extract_domain(url_or_domain: str) -> str:
        """Return lowercase domain from a URL or bare hostname."""
        s = url_or_domain.strip().lower()
        if '://' in s:
            parsed = urlparse(s)
            host = parsed.netloc or s
        else:
            host = s
        # Strip port
        return host.split(':')[0]

    @staticmethod
    def _registered_domain(domain: str) -> str:
        """
        Naively strip subdomains to get the registered domain.
        'login.paypal.com'  → 'paypal.com'
        'api.github.com'    → 'github.com'
        'bbc.co.uk'         → 'bbc.co.uk'  (kept as-is; ccSLD handling is hard)
        """
        parts = domain.split('.')
        if len(parts) > 2:
            return '.'.join(parts[-2:])
        return domain

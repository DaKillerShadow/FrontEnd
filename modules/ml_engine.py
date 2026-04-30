# =============================================================================
# modules/ml_engine.py  —  MLEngine (Feature Extraction + Prediction)
# =============================================================================
# PURPOSE:
#   This is the THIRD layer.  The RuleEngine makes binary (triggered / not-
#   triggered) decisions.  The ML model turns the same information into a
#   continuous *probability* — giving us much finer-grained confidence scores
#   and the ability to catch patterns that no single rule covers.
#
# FEATURE ENGINEERING — WHY THESE FEATURES?
#   We extract 14 numerical features purely from the URL string itself
#   ("lexical features").  This means we NEVER need to visit the URL, which:
#     • Keeps analysis fast (< 1 ms per URL).
#     • Avoids infecting the server with drive-by malware.
#     • Works even for URLs that are already taken down.
#
#   Feature list and rationale:
#   ┌────┬──────────────────────────────────┬─────────────────────────────────┐
#   │ #  │ Feature                          │ Why it matters                  │
#   ├────┼──────────────────────────────────┼─────────────────────────────────┤
#   │  0 │ url_length                       │ Phishing URLs are longer        │
#   │  1 │ hostname_length                  │ Long hostnames look suspicious  │
#   │  2 │ path_length                      │ Deep paths hide payloads        │
#   │  3 │ num_dots                         │ Many dots → many subdomains     │
#   │  4 │ num_hyphens                      │ Hyphens in typosquatting        │
#   │  5 │ num_underscores                  │ Uncommon in legit domains       │
#   │  6 │ num_slashes                      │ Extra slashes → redirect tricks │
#   │  7 │ num_query_params                 │ Lots of params → tracking/redir │
#   │  8 │ num_special_chars (@,%,=,?)      │ Special chars inflate suspicion │
#   │  9 │ has_ip_host            (0/1)     │ IP instead of domain            │
#   │ 10 │ has_https              (0/1)     │ Absence of TLS                  │
#   │ 11 │ has_at_sign            (0/1)     │ @ in URL = redirect trick       │
#   │ 12 │ subdomain_count                  │ Deep subdomain nesting          │
#   │ 13 │ url_entropy                      │ High entropy → random/obfuscated│
#   └────┴──────────────────────────────────┴─────────────────────────────────┘
#
#   Shannon entropy measures "randomness" of the character distribution.
#   Legitimate URLs have low entropy because they contain readable words.
#   Auto-generated phishing subdomains (e.g. "a3xq9r.evil.com") have much
#   higher entropy.
#
# MODEL:
#   We load a Random Forest classifier serialised with joblib.  The model was
#   trained by train_model.py on synthetic data and saved to models/model.pkl.
# =============================================================================

import math
import re
import os
from urllib.parse import urlparse, parse_qs

import joblib
import numpy as np


class MLEngine:
    """Loads a pre-trained classifier and scores URLs using lexical features."""

    # Path to the serialised model, relative to this file's directory.
    MODEL_PATH = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),   # project root
        "models", "model.pkl"
    )

    # Regex to detect an IPv4 address as the host.
    _RE_IP = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$")

    def __init__(self):
        """Load the model once when the engine is instantiated."""
        if not os.path.exists(self.MODEL_PATH):
            raise FileNotFoundError(
                f"Model file not found at {self.MODEL_PATH}. "
                "Please run train_model.py first."
            )
        self.model = joblib.load(self.MODEL_PATH)

    # ── Feature Extraction ─────────────────────────────────────────────────────

    def extract_features(self, url: str) -> dict:
        """
        Parses *url* and returns a dictionary of the 14 numerical features.
        The dictionary keys are human-readable for display in the UI.
        """
        parsed   = urlparse(url)
        hostname = parsed.netloc.lower().split(":")[0]   # strip port
        path     = parsed.path
        query    = parsed.query

        # ── Feature 0: Full URL length ─────────────────────────────────────
        url_length = len(url)

        # ── Feature 1: Hostname length ──────────────────────────────────────
        hostname_length = len(hostname)

        # ── Feature 2: Path length ───────────────────────────────────────────
        path_length = len(path)

        # ── Feature 3: Number of dots in full URL ───────────────────────────
        num_dots = url.count(".")

        # ── Feature 4: Number of hyphens in full URL ────────────────────────
        num_hyphens = url.count("-")

        # ── Feature 5: Number of underscores ────────────────────────────────
        num_underscores = url.count("_")

        # ── Feature 6: Number of slashes in path ────────────────────────────
        # We exclude the two slashes in "http://" by only counting in the path.
        num_slashes = path.count("/")

        # ── Feature 7: Number of query parameters ───────────────────────────
        num_query_params = len(parse_qs(query))

        # ── Feature 8: Number of special characters (@, %, =, ?) ────────────
        num_special_chars = sum(url.count(c) for c in ["@", "%", "=", "?", "!"])

        # ── Feature 9: IP address as host (boolean → int) ───────────────────
        has_ip_host = int(bool(self._RE_IP.match(parsed.netloc)))

        # ── Feature 10: HTTPS used? (boolean → int) ─────────────────────────
        has_https = int(parsed.scheme == "https")

        # ── Feature 11: Contains @ symbol? ──────────────────────────────────
        has_at_sign = int("@" in url)

        # ── Feature 12: Subdomain depth ─────────────────────────────────────
        # Strip "www." then count remaining dot-separated segments.
        clean_host = hostname[4:] if hostname.startswith("www.") else hostname
        subdomain_count = max(0, len(clean_host.split(".")) - 2)
        # e.g. "login.paypal.com" → ["login","paypal","com"] → 3-2 = 1 subdomain

        # ── Feature 13: Shannon entropy of the URL ──────────────────────────
        url_entropy = self._shannon_entropy(url)

        return {
            "url_length":        url_length,
            "hostname_length":   hostname_length,
            "path_length":       path_length,
            "num_dots":          num_dots,
            "num_hyphens":       num_hyphens,
            "num_underscores":   num_underscores,
            "num_slashes":       num_slashes,
            "num_query_params":  num_query_params,
            "num_special_chars": num_special_chars,
            "has_ip_host":       has_ip_host,
            "has_https":         has_https,
            "has_at_sign":       has_at_sign,
            "subdomain_count":   subdomain_count,
            "url_entropy":       round(url_entropy, 4),
        }

    # ── Prediction ─────────────────────────────────────────────────────────────

    def predict(self, features: dict) -> dict:
        """
        Runs the trained classifier on the feature vector.

        Parameters
        ----------
        features : dict   Output of extract_features().

        Returns
        -------
        dict with keys:
            label       str    – "phishing" or "safe"
            probability float  – Probability of being phishing (0.0 – 1.0)
        """
        # Convert feature dict → numpy row vector (preserve column order).
        feature_order = [
            "url_length", "hostname_length", "path_length",
            "num_dots", "num_hyphens", "num_underscores",
            "num_slashes", "num_query_params", "num_special_chars",
            "has_ip_host", "has_https", "has_at_sign",
            "subdomain_count", "url_entropy",
        ]
        X = np.array([[features[k] for k in feature_order]])

        # predict_proba returns [[P(safe), P(phishing)]]
        proba       = self.model.predict_proba(X)[0]
        phishing_prob = float(proba[1])     # probability of class 1 = phishing

        label = "phishing" if phishing_prob >= 0.5 else "safe"

        return {
            "label":       label,
            "probability": round(phishing_prob, 4),
        }

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """
        Computes the Shannon entropy (bits) of *text*.

        H = -∑ p(c) · log₂(p(c))   for each unique character c.

        A URL with only lowercase letters has low entropy (~4 bits).
        A randomly generated subdomain has high entropy (~5–6 bits).
        """
        if not text:
            return 0.0
        n    = len(text)
        freq = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        return -sum((count / n) * math.log2(count / n) for count in freq.values())

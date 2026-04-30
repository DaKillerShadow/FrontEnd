# =============================================================================
# modules/homoglyph_detector.py  —  HomoglyphDetector
# =============================================================================
# PURPOSE:
#   Detect "look-alike" characters (homoglyphs) and typosquatting in URLs.
#   Attackers replace ASCII letters with visually identical Unicode characters
#   (e.g. Cyrillic 'а' \u0430 looks identical to Latin 'a') or substitute
#   characters to create misleading domain names (e.g. g00gle.com).
#
# TECHNIQUES:
#   1. Unicode Confusable Mapping  – map known homoglyph characters to their
#      ASCII equivalents and check if normalised domain matches a well-known brand.
#   2. Levenshtein Distance        – measure edit distance between the domain
#      and every entry in our brand list; flag if distance ≤ 2.
#   3. Digit Substitution          – detect common l33t-speak replacements
#      (0→o, 1→l/i, 3→e, etc.) used to impersonate brands.
# =============================================================================

import unicodedata
import re
from typing import Optional


# ---------------------------------------------------------------------------
# Homoglyph mapping: Unicode codepoints → ASCII equivalent
# Source: Unicode Consortium confusables.txt + common phishing observations
# ---------------------------------------------------------------------------
HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic look-alikes
    '\u0430': 'a',  # Cyrillic small а
    '\u0435': 'e',  # Cyrillic small е
    '\u043e': 'o',  # Cyrillic small о
    '\u0440': 'r',  # Cyrillic small р
    '\u0441': 'c',  # Cyrillic small с
    '\u0443': 'u',  # Cyrillic small у
    '\u0445': 'x',  # Cyrillic small х
    '\u0456': 'i',  # Cyrillic small і
    '\u0458': 'j',  # Cyrillic small ј
    '\u0455': 's',  # Cyrillic small ѕ
    '\u0501': 'd',  # Cyrillic small ԁ
    '\u0570': 'h',  # Armenian small հ
    # Greek look-alikes
    '\u03bf': 'o',  # Greek small omicron
    '\u03c1': 'p',  # Greek small rho
    '\u03b1': 'a',  # Greek small alpha
    '\u03b5': 'e',  # Greek small epsilon
    '\u03b9': 'i',  # Greek small iota
    '\u03bd': 'v',  # Greek small nu
    # Latin extended look-alikes
    '\u00e0': 'a',  # à
    '\u00e1': 'a',  # á
    '\u00e2': 'a',  # â
    '\u00e4': 'a',  # ä
    '\u00e8': 'e',  # è
    '\u00e9': 'e',  # é
    '\u00ec': 'i',  # ì
    '\u00ed': 'i',  # í
    '\u00f2': 'o',  # ò
    '\u00f3': 'o',  # ó
    '\u00f9': 'u',  # ù
    '\u00fa': 'u',  # ú
    # Zero-width and confusing punctuation
    '\u2019': "'",
    '\u2018': "'",
    '\uff0e': '.',  # fullwidth full stop
    '\u3002': '.',  # ideographic full stop
}

# ---------------------------------------------------------------------------
# Common digit-to-letter substitutions used in typosquatting
# ---------------------------------------------------------------------------
DIGIT_SUB_MAP: dict[str, str] = {
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '4': 'a',
    '5': 's',
    '6': 'g',
    '7': 't',
    '8': 'b',
    '9': 'g',
    '@': 'a',
    '$': 's',
    '!': 'i',
}

# ---------------------------------------------------------------------------
# Well-known brand domains to check against (SLD only, no TLD)
# ---------------------------------------------------------------------------
KNOWN_BRANDS: set[str] = {
    'google', 'gmail', 'youtube', 'facebook', 'instagram', 'twitter',
    'microsoft', 'apple', 'amazon', 'netflix', 'paypal', 'ebay',
    'linkedin', 'whatsapp', 'tiktok', 'snapchat', 'pinterest',
    'dropbox', 'spotify', 'airbnb', 'uber', 'netflix',
    'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'barclays',
    'hsbc', 'santander', 'lloyds', 'natwest',
    'icloud', 'outlook', 'yahoo', 'hotmail', 'live',
    'adobe', 'salesforce', 'shopify', 'wordpress', 'github',
}


def _levenshtein(s1: str, s2: str) -> int:
    """
    Standard dynamic-programming Levenshtein distance.
    Returns the minimum number of single-character edits (insert, delete,
    replace) required to transform s1 into s2.
    """
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(
                prev[j + 1] + 1,          # deletion
                curr[j] + 1,              # insertion
                prev[j] + (c1 != c2),     # substitution
            ))
        prev = curr
    return prev[-1]


def _normalise_homoglyphs(text: str) -> str:
    """Replace all known homoglyph characters with their ASCII equivalents."""
    result = []
    for ch in text:
        result.append(HOMOGLYPH_MAP.get(ch, ch))
    # Also apply Unicode NFKC normalisation (e.g. fullwidth→ASCII)
    return unicodedata.normalize('NFKC', ''.join(result))


def _normalise_digits(text: str) -> str:
    """Replace common digit/symbol substitutions with their letter equivalents."""
    return ''.join(DIGIT_SUB_MAP.get(ch, ch) for ch in text)


class HomoglyphDetector:
    """
    Detects homoglyph attacks and typosquatting in domain names.

    Usage
    -----
    detector = HomoglyphDetector()
    result   = detector.check("goog1e.com")
    # → {'is_suspicious': True, 'technique': 'digit_substitution',
    #    'matched_brand': 'google', 'normalised': 'google', ...}
    """

    def check(self, hostname: str) -> dict:
        """
        Run all detection techniques against *hostname*.

        Parameters
        ----------
        hostname : str   The domain to analyse (e.g. "goog1e.com").

        Returns
        -------
        dict:
            is_suspicious  bool   – True if any technique fired.
            technique      str    – Which technique fired (or "none").
            matched_brand  str    – The brand being impersonated (or "").
            normalised     str    – ASCII-normalised version of the domain SLD.
            detail         str    – Human-readable explanation.
            levenshtein_distance int – Edit distance to nearest brand (or -1).
        """
        # Extract second-level domain (SLD) for comparison
        sld = self._extract_sld(hostname)
        if not sld:
            return self._clean_result(sld)

        # ── Technique 1: Homoglyph character substitution ─────────────────
        normalised_hg = _normalise_homoglyphs(sld)
        if normalised_hg != sld and normalised_hg.lower() in KNOWN_BRANDS:
            return {
                'is_suspicious':        True,
                'technique':            'homoglyph_substitution',
                'matched_brand':        normalised_hg.lower(),
                'normalised':           normalised_hg,
                'levenshtein_distance': 0,
                'detail': (
                    f"The domain '{hostname}' contains Unicode look-alike "
                    f"characters. When normalised, it reads '{normalised_hg}' "
                    f"— impersonating the brand '{normalised_hg.lower()}'."
                ),
            }

        # ── Technique 2: Digit substitution (l33t-speak) ──────────────────
        normalised_ds = _normalise_digits(sld.lower())
        if normalised_ds != sld.lower() and normalised_ds in KNOWN_BRANDS:
            return {
                'is_suspicious':        True,
                'technique':            'digit_substitution',
                'matched_brand':        normalised_ds,
                'normalised':           normalised_ds,
                'levenshtein_distance': 0,
                'detail': (
                    f"The domain '{hostname}' uses digit/symbol substitutions "
                    f"(e.g. '0' for 'o', '1' for 'l'). Normalised: '{normalised_ds}' "
                    f"— impersonating '{normalised_ds}'."
                ),
            }

        # ── Technique 3: Levenshtein distance to known brands ─────────────
        sld_clean = sld.lower()
        best_brand: Optional[str] = None
        best_dist = 999
        for brand in KNOWN_BRANDS:
            # Skip if lengths are too different (early exit optimisation)
            if abs(len(sld_clean) - len(brand)) > 3:
                continue
            dist = _levenshtein(sld_clean, brand)
            if dist < best_dist:
                best_dist = dist
                best_brand = brand

        # Distance ≤ 2 and not an exact known-brand match (that would be legit)
        if best_dist <= 2 and best_dist > 0 and best_brand:
            return {
                'is_suspicious':        True,
                'technique':            'levenshtein_typosquatting',
                'matched_brand':        best_brand,
                'normalised':           sld_clean,
                'levenshtein_distance': best_dist,
                'detail': (
                    f"The domain '{sld_clean}' is very similar to the well-known "
                    f"brand '{best_brand}' (edit distance: {best_dist}). "
                    "This is a classic typosquatting pattern."
                ),
            }

        return self._clean_result(sld)

    @staticmethod
    def _extract_sld(hostname: str) -> str:
        """
        Extract the second-level domain (the main brand name part).
        'login.paypal.com' → 'paypal'
        'google.co.uk'     → 'google'
        """
        parts = hostname.lower().lstrip('www.').split('.')
        if len(parts) >= 2:
            return parts[-2]   # second from right is always the SLD
        return hostname

    @staticmethod
    def _clean_result(sld: str) -> dict:
        return {
            'is_suspicious':        False,
            'technique':            'none',
            'matched_brand':        '',
            'normalised':           sld,
            'levenshtein_distance': -1,
            'detail':               '',
        }

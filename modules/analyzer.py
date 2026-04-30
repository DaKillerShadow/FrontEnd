# =============================================================================
# modules/analyzer.py  —  URLAnalyzer (Enhanced Hybrid Orchestrator)
# =============================================================================
# PRESERVED LOGIC (from original):
#   • All verdict thresholds are UNCHANGED:
#       rule_score >= 8 OR ml_prob >= 0.7  →  "likely_phishing"
#       rule_score >= 4 OR ml_prob >= 0.4  →  "suspicious"
#       else                               →  "safe"
#   • Combined hybrid score formula: (ml_prob × 10) + (rule_risk_score × 0.5)
#     (used for display only; verdict uses the OR logic above)
#
# NEW ADDITIONS:
#   1. Tranco Top 100k whitelist check (before ML — reduces false positives)
#   2. Homoglyph / typosquatting detection
#   3. Link masking detection (visible_text vs. href comparison)
#   4. XAI: rich human-readable "why" explanations with feature importance ranks
#   5. Feature importance from the Random Forest model
# =============================================================================

from .validator          import URLValidator
from .rule_engine         import RuleEngine
from .ml_engine           import MLEngine
from .tranco_checker      import TrancoChecker
from .homoglyph_detector  import HomoglyphDetector

# ── Feature Importance & Descriptions (XAI UI) ────────────────────────────────

# Precomputed approximate feature importance ranks including 'is_punycode'
_FEATURE_IMPORTANCE_APPROX: dict[str, float] = {
    'is_punycode':       0.185, # Top feature for homograph detection
    'url_length':        0.130,
    'url_entropy':       0.120,
    'num_special_chars': 0.105,
    'hostname_length':   0.090,
    'path_length':       0.080,
    'num_dots':          0.070,
    'subdomain_count':   0.065,
    'num_slashes':       0.060,
    'has_https':         0.045,
    'num_hyphens':       0.035,
    'has_ip_host':       0.010,
    'num_query_params':  0.005,
    'has_at_sign':       0.000,
    'num_underscores':   0.000,
}

_FEATURE_DESCRIPTIONS: dict[str, str] = {
    'url_length':        'Total URL length — phishing URLs are typically much longer',
    'url_entropy':       'Character randomness — high entropy suggests generated/obfuscated URLs',
    'num_special_chars': 'Special characters (@, %, =, ?) — used to confuse URL parsers',
    'hostname_length':   'Hostname length — long hostnames often embed brand names as decoys',
    'path_length':       'Path depth — deep paths hide malicious payloads',
    'num_dots':          'Dot count — many dots indicate excessive subdomain nesting',
    'subdomain_count':   'Subdomain depth — e.g. "secure.login.paypal.evil.com"',
    'num_slashes':       'Slash count — extra slashes enable redirect tricks',
    'has_https':         'HTTPS presence — absence of TLS is a weak but real signal',
    'num_hyphens':       'Hyphen count — hyphens used in typosquatting (pay-pal.com)',
    'has_ip_host':       'IP as host — raw IP addresses avoid domain registration',
    'num_query_params':  'Query parameter count — many params suggest tracking/redirect',
    'has_at_sign':       '@ symbol — browsers ignore everything before @ in a URL',
    'num_underscores':   'Underscore count — underscores are uncommon in legitimate domains',
    'is_punycode':       'Punycode/Homograph prefix (xn--) — used for look-alike domain attacks',
}

LABEL_MAP = {
    'safe':             '✅  Safe',
    'suspicious':      '⚠️  Suspicious',
    'likely_phishing': '🚨  Likely Phishing',
}

# ── URLAnalyzer Class ────────────────────────────────────────────────────────

class URLAnalyzer:
    """
    Enhanced hybrid orchestrator. Integrates Tranco whitelist, 
    homoglyph detection, link masking, and 15-feature XAI output.
    """

    def __init__(self):
        self.validator         = URLValidator()
        self.rule_engine       = RuleEngine()
        self.ml_engine         = MLEngine()
        self.tranco            = TrancoChecker()
        self.homoglyph         = HomoglyphDetector()
        # Known shorteners that MUST go through full analysis
        self.SHORTENER_DOMAINS = {'tinyurl.com', 'bit.ly', 't.co', 'rb.gy', 'goo.gl', 'is.gd', 'ow.ly'}

    def analyze(self, raw_url: str, visible_text: str = '') -> dict:
        """Full pipeline analysis (Fast Path: static lexical + ML)."""

        # ── Stage 1: Validate & Normalise ──
        validation = self.validator.validate(raw_url)
        if not validation['is_valid']:
            return {
                'success': False, 'error': validation['error'], 'url': raw_url,
                'verdict': None, 'verdict_label': None, 'triggered_rules': [],
                'rule_risk_score': 0, 'ml_result': None, 'features': None,
                'explanation': '', 'whitelist': None, 'homoglyph': None,
                'link_masking': None, 'xai': None, 'combined_score': 0,
            }

        url = validation['url']
        whitelist_result = self.tranco.is_whitelisted(url)
        domain = whitelist_result.get('domain', '').lower()

        # ── Stage 2: Enhanced Whitelist Check (Shortener Bypass Fix) ──
        # Whitelisted domains only exit early if they are NOT known shorteners.
        if whitelist_result['whitelisted'] and domain not in self.SHORTENER_DOMAINS:
            return {
                'success':          True,
                'error':            '',
                'url':              url,
                'verdict':          'safe',
                'verdict_label':    LABEL_MAP['safe'],
                'triggered_rules':  [],
                'rule_risk_score':  0,
                'ml_result':        {'label': 'safe', 'probability': 0.02},
                'features':         self.ml_engine.extract_features(url),
                'explanation':      (
                    f"Domain '{whitelist_result['domain']}' is in the Tranco "
                    f"Top-100k list — a globally recognised, legitimate website."
                ),
                'whitelist':        whitelist_result,
                'homoglyph':        {'is_suspicious': False, 'technique': 'none', 'detail': ''},
                'link_masking':     self._check_link_masking(url, visible_text),
                'xai':              None,
                'combined_score':   0.2,
            }

        # ── Stage 3: Feature Extraction (15 features) ──
        features = self.ml_engine.extract_features(url)

        # ── Stage 4: Homoglyph & Link Masking ──
        from urllib.parse import urlparse
        hostname = urlparse(url).netloc.lower().split(':')[0]
        homoglyph_result = self.homoglyph.check(hostname)
        link_masking_result = self._check_link_masking(url, visible_text)

        # ── Stage 5: Rule & ML Engines ──
        rule_result     = self.rule_engine.analyze(url)
        rule_score      = rule_result['risk_score']
        triggered_rules = rule_result['triggered_rules']

        # Manual escalations
        if domain in self.SHORTENER_DOMAINS:
            triggered_rules.append({
                'name': 'URL Shortener (Analysis Required)',
                'description': 'Known URL shortener detected. Forcing deeper inspection.',
                'severity': 'medium'
            })
            rule_score += 2

        if homoglyph_result['is_suspicious']:
            triggered_rules.append({
                'name': 'Homoglyph / Typosquatting Attack',
                'description': homoglyph_result['detail'],
                'severity': 'high',
            })
            rule_score += 5 

        if link_masking_result['is_masked']:
            triggered_rules.append({
                'name': 'Link Masking Detected',
                'description': link_masking_result['detail'],
                'severity': 'high',
            })
            rule_score += 3

        ml_result = self.ml_engine.predict(features)

        # ── Stage 6: Final Combined Verdict ──
        if rule_score >= 8 or ml_result['probability'] >= 0.7:
            verdict = 'likely_phishing'
        elif rule_score >= 4 or ml_result['probability'] >= 0.4:
            verdict = 'suspicious'
        else:
            verdict = 'safe'

        combined_score = round((ml_result['probability'] * 10) + (rule_score * 0.5), 2)

        return {
            'success':          True,
            'error':            '',
            'url':              url,
            'verdict':          verdict,
            'verdict_label':    LABEL_MAP[verdict],
            'triggered_rules':  triggered_rules,
            'rule_risk_score':  rule_score,
            'ml_result':        ml_result,
            'features':         features,
            'explanation':      self._build_explanation(
                                    verdict, rule_score, ml_result, homoglyph_result, 
                                    link_masking_result, whitelist_result
                                ),
            'whitelist':        whitelist_result,
            'homoglyph':        homoglyph_result,
            'link_masking':     link_masking_result,
            'xai':              self._build_xai(features, ml_result, triggered_rules, verdict),
            'combined_score':   combined_score,
        }

    def get_feature_importances(self) -> list[dict]:
        """Return sorted feature importances for 15 features."""
        try:
            feature_order = [
                'url_length', 'hostname_length', 'path_length', 'num_dots',
                'num_hyphens', 'num_underscores', 'num_slashes', 'num_query_params',
                'num_special_chars', 'has_ip_host', 'has_https', 'has_at_sign',
                'subdomain_count', 'url_entropy', 'is_punycode'
            ]
            importances = self.ml_engine.model.feature_importances_
            result = [
                {'feature': n, 'importance': round(float(imp), 4), 'description': _FEATURE_DESCRIPTIONS.get(n, '')}
                for n, imp in zip(feature_order, importances)
            ]
            return sorted(result, key=lambda x: x['importance'], reverse=True)
        except Exception:
            return [
                {'feature': n, 'importance': i, 'description': _FEATURE_DESCRIPTIONS.get(n, '')}
                for n, i in sorted(_FEATURE_IMPORTANCE_APPROX.items(), key=lambda x: x[1], reverse=True)
            ]

    @staticmethod
    def _check_link_masking(url: str, visible_text: str) -> dict:
        """Detect discrepencies between visible text and actual destination."""
        if not visible_text or not visible_text.strip():
            return {'checked': False, 'is_masked': False, 'detail': 'No visible text provided.'}

        from urllib.parse import urlparse
        import re

        visible = visible_text.strip().lower()
        href_domain = urlparse(url).netloc.lower().split(':')[0]
        domain_pattern = re.compile(r'([a-z0-9\-]+\.[a-z]{2,})', re.IGNORECASE)
        visible_domains = domain_pattern.findall(visible)

        if not visible_domains:
            return {'checked': True, 'is_masked': False, 'detail': 'No domain in visible text.'}

        for visible_domain in visible_domains:
            vd_clean = visible_domain.lower().lstrip('www.')
            hd_clean = href_domain.lstrip('www.')
            if vd_clean not in hd_clean and hd_clean not in vd_clean:
                return {
                    'checked': True, 'is_masked': True,
                    'visible_domain': visible_domain, 'actual_domain': href_domain,
                    'detail': f"Link masking: {visible_domain} vs {href_domain}"
                }
        return {'checked': True, 'is_masked': False, 'detail': 'Domains match.'}

    @staticmethod
    def _build_xai(features: dict, ml_result: dict, triggered_rules: list, verdict: str) -> dict:
        """Build Explainable AI breakdown for 15 features."""
        FEATURE_RANGES = {
            'url_length': (10, 200), 'hostname_length': (3, 80), 'path_length': (0, 120),
            'num_dots': (1, 15), 'num_hyphens': (0, 10), 'num_underscores': (0, 6),
            'num_slashes': (1, 20), 'num_query_params': (0, 12), 'num_special_chars': (0, 15),
            'has_ip_host': (0, 1), 'has_https': (0, 1), 'has_at_sign': (0, 1),
            'subdomain_count': (0, 8), 'url_entropy': (2, 6), 'is_punycode': (0, 1)
        }
        feature_contributions = []
        for fname, fval in features.items():
            lo, hi = FEATURE_RANGES.get(fname, (0, 10))
            span = hi - lo if hi != lo else 1
            normalised = 1.0 - (fval - lo) / span if fname == 'has_https' else min(1.0, max(0.0, (fval - lo) / span))
            importance = _FEATURE_IMPORTANCE_APPROX.get(fname, 0.01)
            feature_contributions.append({
                'feature': fname, 'value': fval, 'normalised': round(normalised, 3),
                'importance': importance, 'contribution': round(normalised * importance, 4),
                'description': _FEATURE_DESCRIPTIONS.get(fname, ''),
                'risk_level': 'high' if normalised > 0.7 else ('medium' if normalised > 0.4 else 'low'),
            })
        feature_contributions.sort(key=lambda x: x['contribution'], reverse=True)
        return {
            'why_summary': f"Classification indicators: {', '.join([f['feature'] for f in feature_contributions[:2]])}",
            'feature_contributions': feature_contributions,
            'ml_probability_pct': round(ml_result['probability'] * 100, 1),
            'rule_count': len(triggered_rules)
        }

    @staticmethod
    def _build_explanation(verdict: str, rule_score: int, ml_result: dict, homoglyph: dict, link_masking: dict, whitelist: dict) -> str:
        """Construct human-readable verdict summary."""
        parts = [f"Hybrid scan complete. Verdict: {verdict.replace('_', ' ').title()}."]
        parts.append(f"ML engine: {ml_result['probability']*100:.1f}% phishing. Rule engine: {rule_score} points.")
        if homoglyph['is_suspicious']: parts.append(f"⚠️ Homoglyph attack: impersonating '{homoglyph['matched_brand']}'.")
        if link_masking.get('is_masked'): parts.append(f"⚠️ Link masking: displayed as '{link_masking['visible_domain']}'.")
        if not whitelist['whitelisted']: parts.append("Domain is NOT in the global whitelist.")
        return ' '.join(parts)
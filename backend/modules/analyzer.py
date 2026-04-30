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

from .validator           import URLValidator
from .rule_engine         import RuleEngine
from .ml_engine           import MLEngine
from .tranco_checker      import TrancoChecker
from .homoglyph_detector  import HomoglyphDetector

# Precomputed approximate feature importance ranks from the trained Random Forest
# (derived from train_model.py output; values reflect the synthetic training set).
# Used for XAI display so we don't need to expose model internals in every response.
_FEATURE_IMPORTANCE_APPROX: dict[str, float] = {
    'url_length':        0.142,
    'url_entropy':       0.128,
    'num_special_chars': 0.115,
    'hostname_length':   0.098,
    'path_length':       0.087,
    'num_dots':          0.079,
    'subdomain_count':   0.071,
    'num_slashes':       0.065,
    'has_https':         0.058,
    'num_hyphens':       0.051,
    'has_ip_host':       0.044,
    'num_query_params':  0.032,
    'has_at_sign':       0.018,
    'num_underscores':   0.012,
}

# Human-readable descriptions for each feature (for XAI UI display)
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
}

LABEL_MAP = {
    'safe':            '✅  Safe',
    'suspicious':      '⚠️  Suspicious',
    'likely_phishing': '🚨  Likely Phishing',
}


class URLAnalyzer:
    """
    Enhanced hybrid orchestrator. Preserved verdict logic; extended with
    Tranco whitelist, homoglyph detection, link masking, and rich XAI output.
    """

    def __init__(self):
        self.validator         = URLValidator()
        self.rule_engine       = RuleEngine()
        self.ml_engine         = MLEngine()
        self.tranco            = TrancoChecker()
        self.homoglyph         = HomoglyphDetector()

    def analyze(self, raw_url: str, visible_text: str = '') -> dict:
        """
        Full pipeline analysis (Fast Path: static lexical + ML).

        Parameters
        ----------
        raw_url      : str   Raw URL from user input or scanned QR code.
        visible_text : str   Hyperlink display text (for link masking check).
                             Empty string means no link masking check.

        Returns
        -------
        dict — complete analysis report (all original fields preserved +
               new fields for Tranco, homoglyph, link_masking, and XAI).
        """

        # ── Stage 1: Validate & Normalise ─────────────────────────────────────
        validation = self.validator.validate(raw_url)
        if not validation['is_valid']:
            return {
                'success':          False,
                'error':            validation['error'],
                'url':              raw_url,
                'verdict':          None,
                'verdict_label':    None,
                'triggered_rules':  [],
                'rule_risk_score':  0,
                'ml_result':        None,
                'features':         None,
                'explanation':      '',
                'whitelist':        None,
                'homoglyph':        None,
                'link_masking':     None,
                'xai':              None,
                'combined_score':   0,
            }

        url = validation['url']

        # ── Stage 2: Tranco Whitelist Check (before ML) ───────────────────────
        whitelist_result = self.tranco.is_whitelisted(url)
        if whitelist_result['whitelisted']:
            # Fast-exit: domain is in Tranco top-100k — almost certainly safe.
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
                    f"Top-100k list ({whitelist_result['source']}) — "
                    "a globally recognised, legitimate website."
                ),
                'whitelist':        whitelist_result,
                'homoglyph':        {'is_suspicious': False, 'technique': 'none', 'detail': ''},
                'link_masking':     self._check_link_masking(url, visible_text),
                'xai':              None,
                'combined_score':   0.2,
            }

        # ── Stage 3: Feature Extraction ───────────────────────────────────────
        features = self.ml_engine.extract_features(url)

        # ── Stage 4: Homoglyph / Typosquatting Detection ──────────────────────
        from urllib.parse import urlparse
        hostname        = urlparse(url).netloc.lower().split(':')[0]
        homoglyph_result = self.homoglyph.check(hostname)

        # ── Stage 5: Link Masking Check ───────────────────────────────────────
        link_masking_result = self._check_link_masking(url, visible_text)

        # ── Stage 6: Run the Rule Engine ──────────────────────────────────────
        rule_result     = self.rule_engine.analyze(url)
        rule_score      = rule_result['risk_score']
        triggered_rules = rule_result['triggered_rules']

        # Inject homoglyph finding as an additional rule hit if detected
        if homoglyph_result['is_suspicious']:
            triggered_rules.append({
                'name':        'Homoglyph / Typosquatting Attack',
                'description': homoglyph_result['detail'],
                'severity':    'high',
            })
            rule_score += 3   # high severity weight

        # Inject link masking as a rule hit if detected
        if link_masking_result['is_masked']:
            triggered_rules.append({
                'name':        'Link Masking Detected',
                'description': link_masking_result['detail'],
                'severity':    'high',
            })
            rule_score += 3

        # ── Stage 7: Always Run the ML Engine ─────────────────────────────────
        ml_result = self.ml_engine.predict(features)

        # ── Stage 8: Combine for Final Verdict (PRESERVED LOGIC) ──────────────
        if rule_score >= 8 or ml_result['probability'] >= 0.7:
            verdict = 'likely_phishing'
        elif rule_score >= 4 or ml_result['probability'] >= 0.4:
            verdict = 'suspicious'
        else:
            verdict = 'safe'

        # Display-only combined score (as per original architecture doc)
        combined_score = round((ml_result['probability'] * 10) + (rule_score * 0.5), 2)

        # ── Stage 9: Build XAI Explanation ────────────────────────────────────
        xai = self._build_xai(features, ml_result, triggered_rules, verdict)

        # ── Stage 10: Build human-readable explanation ─────────────────────────
        explanation = self._build_explanation(
            verdict, rule_score, ml_result, homoglyph_result,
            link_masking_result, whitelist_result,
        )

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
            'explanation':      explanation,
            'whitelist':        whitelist_result,
            'homoglyph':        homoglyph_result,
            'link_masking':     link_masking_result,
            'xai':              xai,
            'combined_score':   combined_score,
        }

    def get_feature_importances(self) -> list[dict]:
        """
        Return feature importances from the live Random Forest model,
        sorted descending by importance. Used by the XAI endpoint.
        """
        try:
            import numpy as np
            feature_order = [
                'url_length', 'hostname_length', 'path_length',
                'num_dots', 'num_hyphens', 'num_underscores',
                'num_slashes', 'num_query_params', 'num_special_chars',
                'has_ip_host', 'has_https', 'has_at_sign',
                'subdomain_count', 'url_entropy',
            ]
            importances = self.ml_engine.model.feature_importances_
            result = [
                {
                    'feature':     name,
                    'importance':  round(float(imp), 4),
                    'description': _FEATURE_DESCRIPTIONS.get(name, ''),
                }
                for name, imp in zip(feature_order, importances)
            ]
            return sorted(result, key=lambda x: x['importance'], reverse=True)
        except Exception:
            # Fallback to approximated values
            return [
                {
                    'feature':     name,
                    'importance':  imp,
                    'description': _FEATURE_DESCRIPTIONS.get(name, ''),
                }
                for name, imp in sorted(
                    _FEATURE_IMPORTANCE_APPROX.items(),
                    key=lambda x: x[1], reverse=True
                )
            ]

    # ── Private Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _check_link_masking(url: str, visible_text: str) -> dict:
        """
        Detect link masking: when the hyperlink display text looks like a
        different (legitimate) domain than the actual href.

        Example: <a href="http://evil.ru/steal">www.paypal.com</a>
        """
        if not visible_text or not visible_text.strip():
            return {
                'checked':   False,
                'is_masked': False,
                'detail':    'No visible text provided for link masking check.',
            }

        from urllib.parse import urlparse
        import re

        visible = visible_text.strip().lower()
        href_domain = urlparse(url).netloc.lower().split(':')[0]

        # Check if visible text looks like a URL/domain
        domain_pattern = re.compile(
            r'([a-z0-9\-]+\.[a-z]{2,})', re.IGNORECASE
        )
        visible_domains = domain_pattern.findall(visible)

        if not visible_domains:
            return {
                'checked':   True,
                'is_masked': False,
                'detail':    'Visible text does not contain a recognisable domain.',
            }

        # Check if any domain in visible text differs from the actual href domain
        for visible_domain in visible_domains:
            vd_clean = visible_domain.lower().lstrip('www.')
            hd_clean = href_domain.lstrip('www.')

            if vd_clean not in hd_clean and hd_clean not in vd_clean:
                return {
                    'checked':   True,
                    'is_masked': True,
                    'visible_domain': visible_domain,
                    'actual_domain':  href_domain,
                    'detail': (
                        f"Link masking detected! The hyperlink displays "
                        f"'{visible_domain}' but actually points to "
                        f"'{href_domain}'. This is a classic phishing technique "
                        "to make malicious links appear legitimate."
                    ),
                }

        return {
            'checked':   True,
            'is_masked': False,
            'detail':    'Visible text domain matches the actual href domain.',
        }

    @staticmethod
    def _build_xai(features: dict, ml_result: dict,
                   triggered_rules: list, verdict: str) -> dict:
        """
        Build an Explainable AI breakdown:
        - Which ML features contributed most to this verdict
        - Which rules fired and why
        - A colour-coded risk contribution for each feature
        """
        # Normalise feature values to [0,1] for display using known safe/phishing ranges
        FEATURE_RANGES = {
            'url_length':        (10, 200),
            'hostname_length':   (3,  80),
            'path_length':       (0,  120),
            'num_dots':          (1,  15),
            'num_hyphens':       (0,  10),
            'num_underscores':   (0,  6),
            'num_slashes':       (1,  20),
            'num_query_params':  (0,  12),
            'num_special_chars': (0,  15),
            'has_ip_host':       (0,  1),
            'has_https':         (0,  1),
            'has_at_sign':       (0,  1),
            'subdomain_count':   (0,  8),
            'url_entropy':       (2,  6),
        }

        feature_contributions = []
        for fname, fval in features.items():
            lo, hi = FEATURE_RANGES.get(fname, (0, 10))
            span   = hi - lo if hi != lo else 1

            # For HTTPS: higher value (1=HTTPS) is SAFER, so invert
            if fname == 'has_https':
                normalised = 1.0 - (fval - lo) / span
            else:
                normalised = min(1.0, max(0.0, (fval - lo) / span))

            importance = _FEATURE_IMPORTANCE_APPROX.get(fname, 0.01)
            contribution = round(normalised * importance, 4)

            feature_contributions.append({
                'feature':      fname,
                'value':        fval,
                'normalised':   round(normalised, 3),
                'importance':   importance,
                'contribution': contribution,
                'description':  _FEATURE_DESCRIPTIONS.get(fname, ''),
                'risk_level':   'high' if normalised > 0.7 else ('medium' if normalised > 0.4 else 'low'),
            })

        # Sort by contribution descending
        feature_contributions.sort(key=lambda x: x['contribution'], reverse=True)

        # Build a plain-English "why" summary
        top_features = [f['feature'] for f in feature_contributions[:3]]
        why_phrases  = [_FEATURE_DESCRIPTIONS.get(f, f) for f in top_features]

        if verdict == 'likely_phishing':
            why_summary = (
                f"This URL was classified as likely phishing primarily because: "
                + '; '.join(why_phrases[:2]) + '. '
                + f"ML model confidence: {ml_result['probability']*100:.1f}% phishing. "
                + f"{len(triggered_rules)} rule(s) fired."
            )
        elif verdict == 'suspicious':
            why_summary = (
                f"This URL shows suspicious characteristics: "
                + '; '.join(why_phrases[:2]) + '. '
                + f"ML model confidence: {ml_result['probability']*100:.1f}% phishing. "
                "Proceed with caution."
            )
        else:
            why_summary = (
                "No significant phishing indicators found. "
                f"ML model confidence: {(1-ml_result['probability'])*100:.1f}% safe. "
                "Standard caution still advised."
            )

        return {
            'why_summary':          why_summary,
            'feature_contributions': feature_contributions,
            'ml_probability_pct':   round(ml_result['probability'] * 100, 1),
            'top_risk_features':    top_features,
            'rule_count':           len(triggered_rules),
            'high_severity_rules':  sum(1 for r in triggered_rules if r.get('severity') == 'high'),
        }

    @staticmethod
    def _build_explanation(verdict: str, rule_score: int, ml_result: dict,
                           homoglyph: dict, link_masking: dict,
                           whitelist: dict) -> str:
        """Build the single human-readable explanation string."""
        parts = [f"Hybrid scan complete. Verdict: {verdict.replace('_', ' ').title()}."]

        parts.append(
            f"ML engine: {ml_result['probability']*100:.1f}% phishing probability. "
            f"Rule engine: {rule_score} risk points."
        )

        if homoglyph['is_suspicious']:
            parts.append(
                f"⚠️ Homoglyph attack detected via {homoglyph['technique'].replace('_', ' ')}: "
                f"impersonating '{homoglyph['matched_brand']}'."
            )

        if link_masking.get('is_masked'):
            parts.append(
                f"⚠️ Link masking: displayed as '{link_masking['visible_domain']}' "
                f"but points to '{link_masking['actual_domain']}'."
            )

        if not whitelist['whitelisted']:
            parts.append("Domain is NOT in the Tranco Top-100k global whitelist.")

        return ' '.join(parts)

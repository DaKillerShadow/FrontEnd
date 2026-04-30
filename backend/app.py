# =============================================================================
# app.py  —  IsThisSafe Enhanced Flask API
# =============================================================================
# ENDPOINTS:
#   GET  /health                → Liveness/readiness probe
#   POST /analyze               → Fast Path (static lexical + ML)
#   POST /deep-analyze          → Deep Path (Selenium + WHOIS + BiTB)
#   POST /intel-loop/ingest     → Ingest new phishing signatures
#   GET  /intel-loop/stats      → Signature database statistics
#   GET  /feature-importances   → XAI: Random Forest feature importance list
#
# SECURITY NOTES:
#   /intel-loop/ingest is protected by an API key in the X-Intel-Key header.
#   Set INTEL_API_KEY environment variable before running in production.
#   Never commit API keys to source control.
#
# CORS:
#   flask-cors is used so the Flutter app (or any origin) can call the API.
#   Restrict CORS origins in production by setting ALLOWED_ORIGINS env var.
# =============================================================================

import os
import logging
from flask        import Flask, request, jsonify
from flask_cors   import CORS

from modules.analyzer      import URLAnalyzer
from modules.deep_analyzer import DeepAnalyzer
from modules.intel_loop    import IntelLoop

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
)
logger = logging.getLogger(__name__)

# ── App init ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r'/*': {'origins': os.getenv('ALLOWED_ORIGINS', '*')}})

# ── Singletons ────────────────────────────────────────────────────────────────
logger.info('Loading URLAnalyzer (ML model + Tranco list)...')
analyzer      = URLAnalyzer()
deep_analyzer = DeepAnalyzer()
intel_loop    = IntelLoop(ml_engine_ref=analyzer.ml_engine)
logger.info('All engines ready.')

INTEL_API_KEY = os.getenv('INTEL_API_KEY', 'changeme-in-production')


# =============================================================================
# Helpers
# =============================================================================

def _require_intel_key() -> bool:
    return request.headers.get('X-Intel-Key', '') == INTEL_API_KEY

def _bad_request(msg: str):
    return jsonify({'success': False, 'error': msg}), 400

def _unauthorised():
    return jsonify({'success': False, 'error': 'Invalid or missing X-Intel-Key header.'}), 401


# =============================================================================
# Routes
# =============================================================================

@app.route('/health', methods=['GET'])
def health():
    """Liveness probe — Flutter app polls this on startup."""
    return jsonify({
        'status':         'ok',
        'tranco_domains': analyzer.tranco.size,
        'model_loaded':   True,
        'intel_sigs':     intel_loop.get_stats()['total_signatures'],
    })


@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Fast Path — static lexical + ML analysis.
    Body: { "url": "...", "visible_text": "..." (optional) }
    """
    data = request.get_json(silent=True)
    if not data or 'url' not in data:
        return _bad_request('Missing required field: url')
    raw_url      = data.get('url', '').strip()
    visible_text = data.get('visible_text', '')
    if not raw_url:
        return _bad_request('url field is empty')
    result = analyzer.analyze(raw_url, visible_text=visible_text)
    return jsonify(result)


@app.route('/deep-analyze', methods=['POST'])
def deep_analyze():
    """
    Deep Path — redirect tracing, WHOIS, Selenium, BiTB, screenshot.
    Body: { "url": "..." }
    Returns combined fast + deep results. Takes 5-30 seconds.
    """
    data = request.get_json(silent=True)
    if not data or 'url' not in data:
        return _bad_request('Missing required field: url')
    raw_url = data.get('url', '').strip()
    if not raw_url:
        return _bad_request('url field is empty')

    from modules.validator import URLValidator
    val = URLValidator().validate(raw_url)
    if not val['is_valid']:
        return _bad_request(f"Invalid URL: {val['error']}")

    fast_result = analyzer.analyze(raw_url)
    deep_result = deep_analyzer.analyze(val['url'])

    # Escalate verdict if deep path uncovers more risk
    verdict = fast_result.get('verdict', 'safe')
    if deep_result['bitb_detected'] or deep_result['newly_registered']:
        verdict = 'likely_phishing'
    elif deep_result['deep_risk_score'] >= 3 and verdict == 'safe':
        verdict = 'suspicious'

    label_map = {
        'safe':            '✅  Safe',
        'suspicious':      '⚠️  Suspicious',
        'likely_phishing': '🚨  Likely Phishing',
    }
    return jsonify({
        'success':             True,
        'fast_path':           fast_result,
        'deep_path':           deep_result,
        'final_verdict':       verdict,
        'final_verdict_label': label_map.get(verdict, verdict),
    })


@app.route('/intel-loop/ingest', methods=['POST'])
def intel_ingest():
    """
    Ingest new confirmed phishing URLs to update the Random Forest model.
    Requires X-Intel-Key header.
    Body: { "urls": [...], "label": 1, "source": "manual" }
    """
    if not _require_intel_key():
        return _unauthorised()
    data = request.get_json(silent=True)
    if not data or 'urls' not in data:
        return _bad_request('Missing required field: urls (list of URL strings)')
    urls   = data.get('urls', [])
    label  = int(data.get('label', 1))
    source = str(data.get('source', 'api'))
    if not isinstance(urls, list) or not urls:
        return _bad_request('urls must be a non-empty list of strings')
    if label not in (0, 1):
        return _bad_request('label must be 0 (safe) or 1 (phishing)')
    result = intel_loop.ingest(urls=urls, label=label, source=source)
    return jsonify(result)


@app.route('/intel-loop/stats', methods=['GET'])
def intel_stats():
    """Return phishing signature database statistics."""
    if not _require_intel_key():
        return _unauthorised()
    return jsonify(intel_loop.get_stats())


@app.route('/feature-importances', methods=['GET'])
def feature_importances():
    """Return Random Forest feature importances for XAI visualisation."""
    importances = analyzer.get_feature_importances()
    return jsonify({'success': True, 'importances': importances})


# =============================================================================
# Error Handlers
# =============================================================================

@app.errorhandler(404)
def not_found(_):
    return jsonify({'success': False, 'error': 'Endpoint not found.'}), 404

@app.errorhandler(405)
def method_not_allowed(_):
    return jsonify({'success': False, 'error': 'Method not allowed.'}), 405

@app.errorhandler(500)
def internal_error(exc):
    logger.exception('Unhandled server error: %s', exc)
    return jsonify({'success': False, 'error': 'Internal server error.'}), 500


# =============================================================================
# Entry Point
# =============================================================================
if __name__ == '__main__':
    port  = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    logger.info('Starting IsThisSafe API on port %d (debug=%s)', port, debug)
    app.run(debug=debug, host='0.0.0.0', port=port)

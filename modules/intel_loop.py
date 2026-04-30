# =============================================================================
# modules/intel_loop.py  —  IntelLoop (Continuous Model Update)
# =============================================================================
# PURPOSE:
#   The Intel Loop endpoint allows security researchers and automated systems
#   to submit new confirmed phishing kit signatures (URLs) which are then:
#     1. Stored in a local signature database (JSON file).
#     2. Used to generate new training samples for the Random Forest model.
#     3. The model is incrementally updated (warm-started) with the new data.
#     4. The updated model.pkl is saved, and the MLEngine reloads it.
#
# DESIGN DECISION — Warm-Start Retraining:
#   Full retraining from scratch on every submission would be too slow for a
#   live API. Instead, we use RandomForestClassifier's warm_start=True to
#   ADD new trees to the existing forest rather than replacing them. This
#   gives the model exposure to new phishing patterns without forgetting
#   what it learned during initial training.
#
# SECURITY WARNING:
#   This endpoint MUST be protected behind authentication (API key or mTLS)
#   in production. Allowing unauthenticated submissions would let an attacker
#   poison the training data and degrade model accuracy.
# =============================================================================

import os
import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional

import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier

logger = logging.getLogger(__name__)

_BASE_DIR    = os.path.dirname(os.path.dirname(__file__))
_MODEL_PATH  = os.path.join(_BASE_DIR, 'models', 'model.pkl')
_SIGS_PATH   = os.path.join(_BASE_DIR, 'data', 'phishing_signatures.json')
_MIN_SAMPLES = 10   # minimum new samples before we trigger a retrain

# Feature column order — MUST match MLEngine.predict() exactly
_FEATURE_ORDER = [
    'url_length', 'hostname_length', 'path_length',
    'num_dots', 'num_hyphens', 'num_underscores',
    'num_slashes', 'num_query_params', 'num_special_chars',
    'has_ip_host', 'has_https', 'has_at_sign',
    'subdomain_count', 'url_entropy',
]


class IntelLoop:
    """
    Manages ingestion of new phishing signatures and incremental model updates.
    """

    def __init__(self, ml_engine_ref=None):
        """
        Parameters
        ----------
        ml_engine_ref : MLEngine | None
            A live reference to the MLEngine instance. If provided, the engine's
            model attribute is hot-reloaded after retraining — no server restart
            needed.
        """
        self._ml_engine  = ml_engine_ref
        self._signatures: list[dict] = []
        os.makedirs(os.path.join(_BASE_DIR, 'data'), exist_ok=True)
        self._load_signatures()

    # ── Public API ─────────────────────────────────────────────────────────────

    def ingest(self, urls: list[str], label: int = 1,
               source: str = 'manual', api_key: str = '') -> dict:
        """
        Ingest a batch of URLs as new labelled training samples.

        Parameters
        ----------
        urls    : list[str]  New phishing (label=1) or safe (label=0) URLs.
        label   : int        Ground truth: 1 = phishing, 0 = safe.
        source  : str        Where did this intel come from? (audit trail)
        api_key : str        API key for authorisation (checked by caller).

        Returns
        -------
        dict — ingestion report including whether retraining was triggered.
        """
        if not urls:
            return {'success': False, 'error': 'No URLs provided.', 'retrained': False}

        # Extract features for each URL
        from .ml_engine import MLEngine
        engine = self._ml_engine or MLEngine()

        ingested = 0
        skipped  = 0
        for url in urls:
            try:
                features = engine.extract_features(url)
                sig = {
                    'url':       url,
                    'label':     label,
                    'features':  features,
                    'source':    source,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                }
                self._signatures.append(sig)
                ingested += 1
            except Exception as exc:
                logger.warning('Failed to extract features for %s: %s', url, exc)
                skipped += 1

        self._save_signatures()
        logger.info('IntelLoop: ingested %d new signatures (label=%d)', ingested, label)

        # Trigger retraining if we've accumulated enough new samples
        retrained      = False
        retrain_detail = ''
        new_sigs_count = len(self._signatures)

        if new_sigs_count >= _MIN_SAMPLES:
            try:
                retrain_result = self._retrain()
                retrained      = True
                retrain_detail = retrain_result['detail']
            except Exception as exc:
                logger.error('Retraining failed: %s', exc)
                retrain_detail = f'Retraining failed: {exc}'

        return {
            'success':         True,
            'ingested':        ingested,
            'skipped':         skipped,
            'total_signatures': new_sigs_count,
            'retrained':       retrained,
            'retrain_detail':  retrain_detail,
            'min_for_retrain': _MIN_SAMPLES,
        }

    def get_stats(self) -> dict:
        """Return statistics about the current signature database."""
        label_counts = {0: 0, 1: 0}
        sources: dict[str, int] = {}
        for sig in self._signatures:
            label_counts[sig.get('label', 1)] += 1
            src = sig.get('source', 'unknown')
            sources[src] = sources.get(src, 0) + 1

        return {
            'total_signatures': len(self._signatures),
            'phishing_count':   label_counts[1],
            'safe_count':       label_counts[0],
            'sources':          sources,
            'model_path':       _MODEL_PATH,
            'model_exists':     os.path.exists(_MODEL_PATH),
        }

    # ── Private helpers ────────────────────────────────────────────────────────

    def _retrain(self) -> dict:
        """
        Warm-start retrain: load existing model, add new trees, save.
        Returns a dict with a human-readable detail string.
        """
        t0 = time.time()

        # Build feature matrix from stored signatures
        X_new = np.array([
            [sig['features'][k] for k in _FEATURE_ORDER]
            for sig in self._signatures
        ])
        y_new = np.array([sig['label'] for sig in self._signatures])

        # Load existing model (must exist — train_model.py run first)
        if not os.path.exists(_MODEL_PATH):
            raise FileNotFoundError(f'Base model not found at {_MODEL_PATH}. '
                                    'Run train_model.py first.')

        model: RandomForestClassifier = joblib.load(_MODEL_PATH)

        # Warm-start: increase n_estimators to add new trees
        old_n = model.n_estimators
        new_n = old_n + max(10, len(self._signatures) // 5)
        model.set_params(warm_start=True, n_estimators=new_n)
        model.fit(X_new, y_new)
        model.set_params(warm_start=False)   # reset for normal inference

        # Save updated model
        joblib.dump(model, _MODEL_PATH)

        # Hot-reload in the live MLEngine reference (no server restart)
        if self._ml_engine is not None:
            self._ml_engine.model = model

        elapsed = time.time() - t0
        detail  = (
            f'Model retrained in {elapsed:.2f}s. '
            f'Trees: {old_n} → {new_n}. '
            f'New samples: {len(self._signatures)} '
            f'(phishing={sum(s["label"]==1 for s in self._signatures)}, '
            f'safe={sum(s["label"]==0 for s in self._signatures)}).'
        )
        logger.info('IntelLoop: %s', detail)
        return {'detail': detail}

    def _load_signatures(self):
        """Load existing signatures from the JSON file."""
        if os.path.exists(_SIGS_PATH):
            try:
                with open(_SIGS_PATH, 'r', encoding='utf-8') as fh:
                    self._signatures = json.load(fh)
                logger.info('IntelLoop: loaded %d existing signatures',
                            len(self._signatures))
            except Exception as exc:
                logger.warning('IntelLoop: could not load signatures: %s', exc)
                self._signatures = []
        else:
            self._signatures = []

    def _save_signatures(self):
        """Persist current signatures to the JSON file."""
        try:
            with open(_SIGS_PATH, 'w', encoding='utf-8') as fh:
                json.dump(self._signatures, fh, indent=2)
        except Exception as exc:
            logger.error('IntelLoop: failed to save signatures: %s', exc)

"""
AI predictor module.

predict_risk()               — Quantum vulnerability score (0-1) + risk level.
predict_migration_priority() — RF classifier: migration priority class + confidence.
calculate_overall_score()    — Weighted combination for the overall score display.
"""
import os
import joblib
import numpy as np

MIGRATION_MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'migration_model.pkl')

MIGRATION_CLASSES = ['Low', 'Medium', 'High', 'Critical']

RF_FEATURE_NAMES = [
    'Algorithm Risk',
    'Key Size Risk',
    'Protocol Risk',
    'Cipher Risk',
    'Header Risk',
    'DNSSEC Risk',
    'Hybrid PQC Risk',
    'Key Exchange Risk',
    'PQC Headers Risk',
]

# Cache the loaded model to avoid reloading on every request
_migration_model = None


def _load_migration_model():
    """Lazily load the RF model, caching it in module state."""
    global _migration_model
    if _migration_model is None:
        try:
            _migration_model = joblib.load(MIGRATION_MODEL_PATH)
        except Exception as e:
            print(f'[AI-PQC] Warning: could not load migration model: {e}')
    return _migration_model


def _build_feature_vector(features):
    """Build the 9-element feature vector from the extracted features dict."""
    return np.array([
        features.get('algorithm_risk', 0.5),
        features.get('key_size_risk', 0.5),
        features.get('protocol_risk', 0.5),
        features.get('cipher_risk', 0.5),
        features.get('header_risk', 0.5),
        features.get('dnssec_risk', 0.5),
        features.get('hybrid_pqc_risk', 1.0),
        features.get('key_exchange_risk', 0.5),
        features.get('pqc_headers_risk', 1.0),
    ], dtype=np.float32)


def predict_risk(features):
    """
    Compute quantum vulnerability score using a weighted combination of the
    first 6 features (algorithm, key size, protocol, cipher, headers, DNSSEC).
    Returns a continuous score [0-1] and a categorical risk level.
    """
    fv = _build_feature_vector(features)

    # Weights for quantum vulnerability scoring (first 6 features)
    weights_6 = np.array([0.30, 0.20, 0.20, 0.10, 0.10, 0.10], dtype=np.float32)
    quantum_score = float(np.clip(np.dot(fv[:6], weights_6), 0.0, 1.0))
    quantum_score = round(quantum_score, 3)

    if quantum_score >= 0.75:
        risk_level = 'Critical'
    elif quantum_score >= 0.55:
        risk_level = 'High'
    elif quantum_score >= 0.35:
        risk_level = 'Medium'
    else:
        risk_level = 'Low'

    # Expose full 9-feature vector for the explainability bars
    full_weights = [0.30, 0.20, 0.20, 0.10, 0.10, 0.10, 0.0, 0.0, 0.0]

    return {
        'score': quantum_score,
        'risk_level': risk_level,
        'feature_vector': fv.tolist(),
        'weights': full_weights,
    }


def predict_migration_priority(features):
    """
    Use the trained Random Forest Classifier to predict migration priority and
    return the prediction confidence + per-feature importances for explainability.
    """
    model = _load_migration_model()
    fv = _build_feature_vector(features).reshape(1, -1)

    if model is not None:
        try:
            pred_idx = int(model.predict(fv)[0])
            probas = model.predict_proba(fv)[0]
            confidence = float(probas[pred_idx])
            priority = MIGRATION_CLASSES[pred_idx]
            importances = model.feature_importances_.tolist()

            return {
                'priority': priority,
                'confidence': round(confidence * 100, 1),
                'class_probabilities': {
                    MIGRATION_CLASSES[i]: round(float(p) * 100, 1)
                    for i, p in enumerate(probas)
                },
                'feature_importances': {
                    RF_FEATURE_NAMES[i]: round(float(imp), 4)
                    for i, imp in enumerate(importances)
                },
                'model': 'Random Forest Classifier',
            }
        except Exception as e:
            print(f'[AI-PQC] RF prediction error: {e}')

    # Fallback: rule-based classification when model unavailable
    return _rule_based_priority(features)


def _rule_based_priority(features):
    """Fallback rule-based priority when the RF model is unavailable."""
    hybrid_pqc = features.get('hybrid_pqc_risk', 1.0)
    algo = features.get('algorithm_risk', 0.5)
    proto = features.get('protocol_risk', 0.5)
    key = features.get('key_size_risk', 0.5)
    header = features.get('header_risk', 0.5)
    uniform_importance = round(1.0 / 9, 4)

    if hybrid_pqc < 0.3 or algo < 0.1:
        priority, confidence = 'Low', 70.0
    elif proto >= 0.8 or key >= 0.9:
        priority, confidence = 'Critical', 75.0
    elif proto <= 0.15 and header <= 0.35:
        priority, confidence = 'Medium', 68.0
    else:
        priority, confidence = 'High', 72.0

    return {
        'priority': priority,
        'confidence': confidence,
        'class_probabilities': {c: 25.0 for c in MIGRATION_CLASSES},
        'feature_importances': {n: uniform_importance for n in RF_FEATURE_NAMES},
        'model': 'Rule-Based Fallback',
    }


def calculate_overall_score(quantum_risk_score, headers_score):
    """Weighted composite score combining quantum risk and header security."""
    raw = (quantum_risk_score * 0.70) + ((1.0 - headers_score / 100.0) * 0.30)
    return round(max(0.0, min(1.0, raw)), 3)

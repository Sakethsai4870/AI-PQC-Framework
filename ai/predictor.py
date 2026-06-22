import os
import json
import joblib
import numpy as np

MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'risk_model.pkl')


def _build_feature_vector(features):
    return [
        features.get('algorithm_risk', 0.5),
        features.get('key_size_risk', 0.5),
        features.get('protocol_risk', 0.5),
        features.get('cipher_risk', 0.5),
        features.get('header_risk', 0.5),
        features.get('dnssec_risk', 0.5),
    ]


def predict_risk(features):
    feature_vector = _build_feature_vector(features)

    weights = [0.30, 0.20, 0.20, 0.10, 0.10, 0.10]
    weighted_score = sum(f * w for f, w in zip(feature_vector, weights))
    score = round(min(1.0, max(0.0, weighted_score)), 3)

    if score >= 0.75:
        risk_level = 'Critical'
    elif score >= 0.55:
        risk_level = 'High'
    elif score >= 0.35:
        risk_level = 'Medium'
    else:
        risk_level = 'Low'

    return {
        'score': score,
        'risk_level': risk_level,
        'feature_vector': feature_vector,
        'weights': weights,
    }


def calculate_overall_score(quantum_risk_score, headers_score):
    quantum_weight = 0.70
    header_weight = 0.30
    raw = (quantum_risk_score * quantum_weight) + ((1 - headers_score / 100) * header_weight)
    return round(max(0.0, min(1.0, raw)), 3)

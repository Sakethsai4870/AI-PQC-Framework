"""
Train a Random Forest Classifier for migration priority prediction.

Training Dataset: Synthetic dataset derived from public website security research,
                  simulating real-world cryptographic configurations.

Features (9):
  0  Algorithm Risk       - Certificate algorithm quantum vulnerability
  1  Key Size Risk        - Key size adequacy risk
  2  Protocol Risk        - TLS/SSL version risk
  3  Cipher Risk          - Cipher suite risk
  4  Header Risk          - Missing HTTP security headers risk
  5  DNSSEC Risk          - DNSSEC deployment status
  6  Hybrid PQC Risk      - Hybrid PQC deployment (0=active, 1=absent)
  7  Key Exchange Risk    - Key exchange algorithm quantum risk
  8  PQC Headers Risk     - X-PQC-* header coverage

Output Classes:
  0  Low      - Strong quantum readiness (hybrid PQC deployed or PQC algorithm)
  1  Medium   - Manageable risk (TLS 1.3 + classical algo + strong headers)
  2  High     - Significant risk (classical crypto, no PQC, weak/moderate config)
  3  Critical - Immediate action required (legacy TLS or critically weak keys)
"""
import numpy as np
import os
import joblib


MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'migration_model.pkl')
CLASSES = ['Low', 'Medium', 'High', 'Critical']


def generate_training_data(n_samples=2000):
    """
    Generate synthetic training data representing real-world website crypto configurations.
    500 samples per class with realistic feature distributions and Gaussian noise.
    """
    np.random.seed(42)
    X = []
    y = []
    per_class = n_samples // 4

    def clip(v):
        return float(np.clip(v, 0.0, 1.0))

    def noise(scale=0.03):
        return np.random.normal(0, scale)

    # ── Class 0: LOW ─────────────────────────────────────────────────────────
    # Profile: Hybrid PQC deployed OR PQC-native certificate algorithm.
    # Typical sites: forward-looking deployments, research servers, Cloudflare PQC beta.
    for _ in range(per_class):
        is_pqc_algo = np.random.random() < 0.4
        algo_risk  = clip((0.0 if is_pqc_algo else np.random.choice([0.85, 0.9])) + noise())
        key_risk   = clip((0.0 if is_pqc_algo else np.random.uniform(0.3, 0.6)) + noise())
        proto_risk = clip(np.random.choice([0.1, 0.1, 0.4]) + noise())
        cipher_risk = clip(np.random.uniform(0.0, 0.25) + noise())
        header_risk = clip(np.random.uniform(0.0, 0.45) + noise())
        dnssec_risk = np.random.choice([0.3, 0.7], p=[0.5, 0.5])
        hybrid_risk = clip(np.random.uniform(0.0, 0.2) + noise())   # hybrid active
        ke_risk     = clip(np.random.uniform(0.0, 0.25) + noise())   # ML-KEM / X25519
        pqc_h_risk  = clip(np.random.uniform(0.0, 0.35) + noise())   # PQC headers present
        X.append([algo_risk, key_risk, proto_risk, cipher_risk,
                  header_risk, dnssec_risk, hybrid_risk, ke_risk, pqc_h_risk])
        y.append(0)

    # ── Class 1: MEDIUM ───────────────────────────────────────────────────────
    # Profile: TLS 1.3 + classical cert + strong security headers + no hybrid PQC.
    # Typical: well-configured modern sites (Google, major CDNs).
    for _ in range(per_class):
        algo_risk   = clip(np.random.choice([0.85, 0.9]) + noise())
        key_risk    = clip(np.random.uniform(0.4, 0.75) + noise())
        proto_risk  = clip(0.1 + noise(0.02))              # TLS 1.3
        cipher_risk = clip(np.random.uniform(0.1, 0.35) + noise())
        header_risk = clip(np.random.uniform(0.0, 0.35) + noise())   # strong headers
        dnssec_risk = np.random.choice([0.3, 0.7], p=[0.4, 0.6])
        hybrid_risk = clip(np.random.uniform(0.75, 1.0) + noise(0.02))  # no hybrid PQC
        ke_risk     = clip(np.random.uniform(0.2, 0.55) + noise())   # ECDHE / X25519
        pqc_h_risk  = clip(np.random.uniform(0.7, 1.0) + noise(0.02))  # no PQC headers
        X.append([algo_risk, key_risk, proto_risk, cipher_risk,
                  header_risk, dnssec_risk, hybrid_risk, ke_risk, pqc_h_risk])
        y.append(1)

    # ── Class 2: HIGH ─────────────────────────────────────────────────────────
    # Profile: TLS 1.2/1.3 + classical cert + weak/moderate headers + no hybrid PQC.
    # Typical: average enterprise sites, older SaaS without security hardening.
    for _ in range(per_class):
        algo_risk   = clip(np.random.choice([0.85, 0.9, 0.95]) + noise())
        key_risk    = clip(np.random.uniform(0.5, 0.82) + noise())
        proto_risk  = clip(np.random.choice([0.1, 0.4, 0.4]) + noise())
        cipher_risk = clip(np.random.uniform(0.2, 0.65) + noise())
        header_risk = clip(np.random.uniform(0.45, 0.9) + noise())   # poor headers
        dnssec_risk = np.random.choice([0.3, 0.7], p=[0.25, 0.75])
        hybrid_risk = clip(np.random.uniform(0.85, 1.0) + noise(0.01))  # definitely no PQC
        ke_risk     = clip(np.random.uniform(0.45, 0.92) + noise())   # DHE / RSA KE
        pqc_h_risk  = clip(np.random.uniform(0.85, 1.0) + noise(0.01))
        X.append([algo_risk, key_risk, proto_risk, cipher_risk,
                  header_risk, dnssec_risk, hybrid_risk, ke_risk, pqc_h_risk])
        y.append(2)

    # ── Class 3: CRITICAL ─────────────────────────────────────────────────────
    # Profile: Legacy TLS (≤1.1) OR RSA key < 2048 bits + no PQC mitigations.
    # Typical: legacy servers, IoT devices, old banking backends.
    for _ in range(per_class):
        algo_risk   = clip(np.random.choice([0.9, 0.95, 0.85]) + noise())
        key_risk    = clip(np.random.uniform(0.8, 1.0) + noise(0.02))  # critically small key
        proto_risk  = clip(np.random.choice([0.8, 0.9, 1.0]) + noise(0.02))  # legacy TLS
        cipher_risk = clip(np.random.uniform(0.5, 1.0) + noise())
        header_risk = clip(np.random.uniform(0.6, 1.0) + noise())
        dnssec_risk = 0.7
        hybrid_risk = 1.0                              # no hybrid PQC
        ke_risk     = clip(np.random.uniform(0.65, 1.0) + noise())
        pqc_h_risk  = 1.0                              # no PQC headers
        X.append([algo_risk, key_risk, proto_risk, cipher_risk,
                  header_risk, dnssec_risk, hybrid_risk, ke_risk, pqc_h_risk])
        y.append(3)

    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32)


def train_model():
    """Train and persist the Random Forest migration priority classifier."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import cross_val_score

    print('[AI-PQC] Training Random Forest migration priority classifier...')
    X, y = generate_training_data(n_samples=2000)

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X, y)

    cv_scores = cross_val_score(model, X, y, cv=5, scoring='accuracy')
    print(f'[AI-PQC] Cross-validation accuracy: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}')

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f'[AI-PQC] Model saved → {MODEL_PATH}')
    return model


def ensure_model_trained():
    """Train the model only if the saved file does not exist."""
    if not os.path.exists(MODEL_PATH):
        return train_model()
    return None


if __name__ == '__main__':
    train_model()

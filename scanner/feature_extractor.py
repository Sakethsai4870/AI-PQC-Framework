def extract_features(ssl_data, domain_data, header_data):
    """
    Extract 9 features from scan data for both quantum vulnerability scoring
    and the Random Forest migration priority classifier.

    Features:
      0  algorithm_risk     - Certificate algorithm quantum vulnerability [0-1]
      1  key_size_risk      - Key size adequacy risk [0-1]
      2  protocol_risk      - TLS version risk [0-1]
      3  cipher_risk        - Cipher suite risk [0-1]
      4  header_risk        - Missing HTTP security headers risk [0-1]
      5  dnssec_risk        - DNSSEC deployment status risk [0-1]
      6  hybrid_pqc_risk    - Hybrid PQC deployment status [0=active, 1=absent]
      7  key_exchange_risk  - Key exchange algorithm quantum risk [0-1]
      8  pqc_headers_risk   - X-PQC-* header coverage [0=all present, 1=none]
    """
    features = {}

    algorithm = ssl_data.get('key_algorithm', 'Unknown')
    key_size = ssl_data.get('key_size', 0) or 0

    # Feature 0: Algorithm quantum risk
    algorithm_risk_map = {
        'RSA': 0.9,
        'ECDSA': 0.85,
        'DSA': 0.95,
        'Ed25519': 0.7,
        'Ed448': 0.65,
        'ML-DSA': 0.0,
        'SLH-DSA': 0.0,
        'FN-DSA': 0.0,
        'Unknown': 0.5,
    }
    features['algorithm_risk'] = algorithm_risk_map.get(algorithm, 0.5)

    # Feature 1: Key size risk
    if algorithm == 'RSA':
        if key_size < 2048:
            features['key_size_risk'] = 1.0
        elif key_size < 4096:
            features['key_size_risk'] = 0.7
        else:
            features['key_size_risk'] = 0.4
    elif algorithm == 'ECDSA':
        if key_size < 256:
            features['key_size_risk'] = 0.9
        elif key_size < 384:
            features['key_size_risk'] = 0.7
        else:
            features['key_size_risk'] = 0.5
    elif algorithm in ('ML-DSA', 'SLH-DSA', 'FN-DSA'):
        features['key_size_risk'] = 0.0
    else:
        features['key_size_risk'] = 0.5

    # Feature 2: Protocol risk
    ssl_version = ssl_data.get('ssl_version', '')
    version_risk_map = {
        'SSLv2': 1.0,
        'SSLv3': 1.0,
        'TLSv1': 0.9,
        'TLSv1.1': 0.8,
        'TLSv1.2': 0.4,
        'TLSv1.3': 0.1,
    }
    features['protocol_risk'] = version_risk_map.get(ssl_version, 0.5)

    # Feature 3: Cipher suite risk
    cipher = ssl_data.get('cipher_suite', '') or ''
    cipher_upper = cipher.upper()
    if any(w in cipher_upper for w in ('RC4', '3DES', 'DES', 'NULL', 'EXPORT', 'ANON')):
        features['cipher_risk'] = 1.0
    elif 'AES_256' in cipher_upper or 'AES256' in cipher_upper or 'CHACHA20' in cipher_upper:
        features['cipher_risk'] = 0.1
    elif 'AES_128' in cipher_upper or 'AES128' in cipher_upper:
        features['cipher_risk'] = 0.3
    else:
        features['cipher_risk'] = 0.5

    # Feature 4: HTTP security header risk
    header_score = header_data.get('score', 0) / 100.0
    features['header_security'] = header_score
    features['header_risk'] = round(1.0 - header_score, 3)

    # Feature 5: DNSSEC risk
    features['dnssec_risk'] = 0.3 if domain_data.get('dnssec_enabled') else 0.7

    # Feature 6: Hybrid PQC risk (0=active, 1=absent)
    hybrid_pqc = header_data.get('hybrid_pqc_detected', False)
    features['hybrid_pqc_risk'] = 0.0 if hybrid_pqc else 1.0

    # Feature 7: Key exchange algorithm risk
    cipher_upper = (ssl_data.get('cipher_suite', '') or '').upper()
    if 'ML-KEM' in cipher_upper or 'KYBER' in cipher_upper:
        ke_risk = 0.0
    elif 'X25519' in cipher_upper:
        ke_risk = 0.2
    elif 'ECDHE' in cipher_upper or 'ECDH' in cipher_upper:
        ke_risk = 0.45
    elif 'DHE' in cipher_upper or 'EDH' in cipher_upper:
        ke_risk = 0.65
    elif 'RSA' in cipher_upper:
        ke_risk = 0.9
    else:
        ke_risk = 0.5  # Unknown (Not Observable)
    features['key_exchange_risk'] = ke_risk

    # Feature 8: PQC headers risk (how many of 4 X-PQC-* headers are present)
    pqc_headers = header_data.get('pqc_headers', {})
    n_pqc_headers = len(pqc_headers)
    features['pqc_headers_risk'] = round((4 - min(n_pqc_headers, 4)) / 4.0, 3)

    return features

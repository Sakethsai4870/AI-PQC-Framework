def extract_features(ssl_data, domain_data, header_data):
    features = {}

    algorithm = ssl_data.get('key_algorithm', 'Unknown')
    key_size = ssl_data.get('key_size', 0) or 0

    algorithm_risk = {
        'RSA': 0.9,
        'ECDSA': 0.85,
        'DSA': 0.95,
        'Ed25519': 0.1,
        'Ed448': 0.1,
        'Unknown': 0.5,
    }
    features['algorithm_risk'] = algorithm_risk.get(algorithm, 0.5)

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
    else:
        features['key_size_risk'] = 0.5

    ssl_version = ssl_data.get('ssl_version', '')
    version_risk = {
        'SSLv2': 1.0,
        'SSLv3': 1.0,
        'TLSv1': 0.9,
        'TLSv1.1': 0.8,
        'TLSv1.2': 0.4,
        'TLSv1.3': 0.1,
    }
    features['protocol_risk'] = version_risk.get(ssl_version, 0.5)

    header_score = header_data.get('score', 0) / 100.0
    features['header_security'] = header_score
    features['header_risk'] = 1.0 - header_score

    features['dnssec_risk'] = 0.3 if domain_data.get('dnssec_enabled') else 0.7

    cipher = ssl_data.get('cipher_suite', '') or ''
    if 'RC4' in cipher or 'DES' in cipher or 'NULL' in cipher or 'EXPORT' in cipher:
        features['cipher_risk'] = 1.0
    elif 'AES_128' in cipher or 'AES128' in cipher:
        features['cipher_risk'] = 0.3
    elif 'AES_256' in cipher or 'AES256' in cipher or 'CHACHA20' in cipher:
        features['cipher_risk'] = 0.1
    else:
        features['cipher_risk'] = 0.5

    return features

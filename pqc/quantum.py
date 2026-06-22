QUANTUM_VULNERABLE_ALGORITHMS = {
    'RSA': {
        'vulnerable': True,
        'threat': 'Shor\'s algorithm can factor RSA keys in polynomial time on a sufficiently large quantum computer.',
        'timeline': 'At risk within 10-15 years',
        'severity': 'Critical',
    },
    'ECDSA': {
        'vulnerable': True,
        'threat': 'Shor\'s algorithm can solve the elliptic curve discrete logarithm problem, breaking ECDSA.',
        'timeline': 'At risk within 10-15 years',
        'severity': 'Critical',
    },
    'DSA': {
        'vulnerable': True,
        'threat': 'Shor\'s algorithm can solve the discrete logarithm problem, breaking DSA.',
        'timeline': 'At risk within 10-15 years',
        'severity': 'Critical',
    },
    'Ed25519': {
        'vulnerable': True,
        'threat': 'Quantum computers using Shor\'s algorithm can break elliptic curve-based signatures.',
        'timeline': 'At risk within 15-20 years',
        'severity': 'High',
    },
    'Ed448': {
        'vulnerable': True,
        'threat': 'Quantum computers using Shor\'s algorithm can break elliptic curve-based signatures.',
        'timeline': 'At risk within 15-20 years',
        'severity': 'High',
    },
}

NIST_PQC_STANDARDS = {
    'ML-KEM': {
        'formerly': 'KYBER',
        'type': 'Key Encapsulation Mechanism',
        'status': 'NIST Standard (FIPS 203)',
        'use_case': 'Key exchange and encryption',
        'security_level': 'NIST Level 1, 3, or 5',
        'description': 'Lattice-based KEM providing strong quantum resistance for key establishment.',
    },
    'ML-DSA': {
        'formerly': 'DILITHIUM',
        'type': 'Digital Signature',
        'status': 'NIST Standard (FIPS 204)',
        'use_case': 'Digital signatures',
        'security_level': 'NIST Level 2, 3, or 5',
        'description': 'Lattice-based digital signature scheme offering quantum-resistant authentication.',
    },
    'SLH-DSA': {
        'formerly': 'SPHINCS+',
        'type': 'Digital Signature',
        'status': 'NIST Standard (FIPS 205)',
        'use_case': 'Digital signatures (stateless hash-based)',
        'security_level': 'NIST Level 1, 3, or 5',
        'description': 'Hash-based signature scheme with conservative security assumptions.',
    },
    'FN-DSA': {
        'formerly': 'FALCON',
        'type': 'Digital Signature',
        'status': 'NIST Standard (FIPS 206)',
        'use_case': 'Digital signatures (compact)',
        'security_level': 'NIST Level 1 or 5',
        'description': 'Compact lattice-based signature scheme suitable for bandwidth-constrained environments.',
    },
}

HYBRID_APPROACHES = [
    {
        'name': 'X25519 + ML-KEM-768',
        'description': 'Combine classical ECDH with post-quantum ML-KEM for defense-in-depth.',
        'use_case': 'TLS key exchange',
        'support': 'Supported in TLS 1.3 hybrid mode (draft-ietf-tls-hybrid-design)',
    },
    {
        'name': 'RSA-4096 + SLH-DSA',
        'description': 'Classical RSA signature alongside hash-based post-quantum signature.',
        'use_case': 'Certificate signing',
        'support': 'Transitional approach for certificate authorities',
    },
]


def assess_quantum_risk(algorithm, key_size, ssl_version):
    risk = {
        'algorithm': algorithm,
        'vulnerable': False,
        'threat_description': '',
        'timeline': '',
        'severity': 'Low',
        'score': 0.0,
    }

    algo_info = QUANTUM_VULNERABLE_ALGORITHMS.get(algorithm)
    if algo_info:
        risk['vulnerable'] = algo_info['vulnerable']
        risk['threat_description'] = algo_info['threat']
        risk['timeline'] = algo_info['timeline']
        risk['severity'] = algo_info['severity']

        base_score = 0.9 if algorithm in ('RSA', 'ECDSA', 'DSA') else 0.7

        if algorithm == 'RSA' and key_size:
            if key_size < 2048:
                base_score = 1.0
            elif key_size >= 4096:
                base_score = 0.75

        version_penalty = {
            'TLSv1': 0.1,
            'TLSv1.1': 0.05,
            'TLSv1.2': 0.0,
            'TLSv1.3': -0.1,
        }
        base_score += version_penalty.get(ssl_version, 0.0)
        risk['score'] = max(0.0, min(1.0, base_score))
    else:
        risk['score'] = 0.2
        risk['severity'] = 'Low'
        risk['threat_description'] = 'Algorithm not recognized or not yet assessed for quantum vulnerability.'

    return risk

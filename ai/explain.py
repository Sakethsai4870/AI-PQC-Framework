FEATURE_NAMES = [
    'Algorithm Risk',
    'Key Size Risk',
    'Protocol Risk',
    'Cipher Risk',
    'Header Risk',
    'DNSSEC Risk',
]

FEATURE_DESCRIPTIONS = {
    'Algorithm Risk': 'How vulnerable the signing/encryption algorithm is to quantum attacks.',
    'Key Size Risk': 'Whether the key size provides adequate security against classical and quantum threats.',
    'Protocol Risk': 'Whether the TLS/SSL protocol version is secure and up-to-date.',
    'Cipher Risk': 'How secure the cipher suite is against known cryptographic attacks.',
    'Header Risk': 'Missing or misconfigured HTTP security headers.',
    'DNSSEC Risk': 'Whether DNS responses are cryptographically authenticated.',
}


def explain_prediction(features, prediction):
    feature_vector = prediction.get('feature_vector', [])
    weights = prediction.get('weights', [])

    contributions = []
    for i, (name, value, weight) in enumerate(zip(FEATURE_NAMES, feature_vector, weights)):
        contribution = value * weight
        contributions.append({
            'feature': name,
            'description': FEATURE_DESCRIPTIONS.get(name, ''),
            'value': round(value, 3),
            'weight': weight,
            'contribution': round(contribution, 3),
            'impact': _get_impact_label(contribution),
        })

    contributions.sort(key=lambda x: x['contribution'], reverse=True)
    summary = _generate_summary(contributions, prediction['risk_level'])

    return {
        'contributions': contributions,
        'top_risk_factor': contributions[0]['feature'] if contributions else 'Unknown',
        'summary': summary,
        'risk_level': prediction['risk_level'],
        'score': prediction['score'],
    }


def generate_ai_decision_explanation(ssl_data, domain_data, header_data, recommendations):
    profile = recommendations.get('profile', {})
    migration_priority = recommendations.get('migration_priority', 'Unknown')
    factors = []

    algorithm = profile.get('algorithm', 'Unknown')
    ssl_version = profile.get('ssl_version', '')
    key_size = profile.get('key_size', 0) or 0
    cipher_suite = profile.get('cipher_suite', '')
    cipher_strength = profile.get('cipher_strength', 'Unknown')
    key_exchange = profile.get('key_exchange', 'Unknown')
    hybrid_pqc = profile.get('hybrid_pqc', False)
    pqc_headers = profile.get('pqc_headers', {})
    headers_score = profile.get('headers_score', 0)
    dnssec = profile.get('dnssec', False)
    missing_headers = profile.get('missing_headers', [])
    is_pqc_algo = profile.get('is_pqc_algo', False)

    if algorithm in ('RSA', 'ECDSA', 'DSA'):
        factors.append({
            'factor': f'Classical signature algorithm detected ({algorithm})',
            'impact': 'Negative',
            'detail': (
                f'{algorithm} relies on mathematical hardness problems (integer factorization or discrete '
                'logarithm) that Shor\'s algorithm solves in polynomial time on a cryptographically '
                'relevant quantum computer. This is the primary driver of quantum vulnerability.'
            ),
        })
    elif is_pqc_algo:
        factors.append({
            'factor': f'Post-quantum certificate algorithm in use ({algorithm})',
            'impact': 'Positive',
            'detail': (
                f'{algorithm} is a NIST-standardized post-quantum algorithm resistant to both '
                'classical and quantum attacks. This significantly reduces certificate-level quantum risk.'
            ),
        })
    else:
        factors.append({
            'factor': f'Unrecognized or unclassified certificate algorithm ({algorithm})',
            'impact': 'Neutral',
            'detail': (
                f'Algorithm {algorithm} was not matched against known quantum-vulnerable or '
                'quantum-resistant categories. Manual review of the certificate chain is recommended.'
            ),
        })

    if hybrid_pqc:
        factors.append({
            'factor': f'Hybrid post-quantum deployment detected ({", ".join(pqc_headers.keys())})',
            'impact': 'Positive',
            'detail': (
                'Custom PQC headers are present, indicating an active hybrid post-quantum deployment. '
                'This reduces migration urgency significantly as key exchange is already protected. '
                f'Detected: {"; ".join(f"{k}={v}" for k, v in pqc_headers.items())}.'
            ),
        })
    else:
        factors.append({
            'factor': 'Hybrid post-quantum key exchange not detected',
            'impact': 'Negative',
            'detail': (
                'No X-PQC-* headers were detected, indicating that hybrid ML-KEM or other '
                'post-quantum key exchange mechanisms are not deployed. '
                'Key exchange remains vulnerable to "harvest now, decrypt later" attacks.'
            ),
        })

    if ssl_version == 'TLSv1.3':
        factors.append({
            'factor': 'TLS 1.3 in use — modern protocol supports hybrid PQC groups',
            'impact': 'Positive',
            'detail': (
                'TLS 1.3 supports hybrid key exchange groups (X25519+ML-KEM-768) defined in '
                'IETF draft-ietf-tls-hybrid-design. This makes deploying quantum-safe key exchange '
                'straightforward without breaking backward compatibility.'
            ),
        })
    elif ssl_version == 'TLSv1.2':
        factors.append({
            'factor': 'TLS 1.2 in use — upgrade required before PQC hybrid deployment',
            'impact': 'Negative',
            'detail': (
                'TLS 1.2 does not support hybrid PQC key exchange groups. '
                'Upgrading to TLS 1.3 is a prerequisite for deploying ML-KEM hybrid key exchange.'
            ),
        })
    else:
        factors.append({
            'factor': f'Deprecated TLS version in use ({ssl_version})',
            'impact': 'Negative',
            'detail': (
                f'{ssl_version} carries known exploitable classical vulnerabilities in addition to '
                'having no path to post-quantum compatibility. Immediate protocol upgrade required.'
            ),
        })

    if algorithm == 'RSA' and key_size > 0:
        if key_size < 2048:
            factors.append({
                'factor': f'Critically undersized RSA key ({key_size} bits)',
                'impact': 'Negative',
                'detail': (
                    f'RSA-{key_size} is below the NIST minimum of 2048 bits for classical security. '
                    'This key is at risk from both classical attacks today and quantum attacks in the future.'
                ),
            })
        elif key_size >= 4096:
            factors.append({
                'factor': f'Large RSA key size ({key_size} bits) — marginally higher classical safety',
                'impact': 'Neutral',
                'detail': (
                    f'RSA-{key_size} provides stronger classical security than smaller RSA keys. '
                    'However, key size does not provide quantum resistance — Shor\'s algorithm breaks '
                    'RSA regardless of key size given a sufficiently powerful quantum computer.'
                ),
            })

    if cipher_strength == 'Strong':
        factors.append({
            'factor': f'Strong symmetric cipher in use ({cipher_suite})',
            'impact': 'Positive',
            'detail': (
                f'AES-256 and ChaCha20 provide 128-bit post-quantum security against Grover\'s algorithm '
                '(which halves effective key strength). The symmetric layer of this TLS session '
                'is quantum-resistant. The asymmetric components (key exchange, certificate) are not.'
            ),
        })
    elif cipher_strength in ('Weak', 'Broken'):
        factors.append({
            'factor': f'Weak or broken cipher suite detected ({cipher_suite})',
            'impact': 'Negative',
            'detail': (
                f'{cipher_suite} is considered cryptographically weak or broken by classical standards. '
                'Replace with AES-256-GCM or CHACHA20-POLY1305 regardless of quantum concerns.'
            ),
        })

    if headers_score >= 70:
        factors.append({
            'factor': f'Security headers well-configured ({headers_score:.0f}% coverage)',
            'impact': 'Positive',
            'detail': (
                f'{headers_score:.0f}% of recommended security headers are present. '
                'Strong HTTP security posture supports a controlled, phased PQC migration '
                'and reduces risk of TLS downgrade attacks that could expose session keys.'
            ),
        })
    elif headers_score >= 40:
        factors.append({
            'factor': f'Security headers partially configured ({headers_score:.0f}% coverage)',
            'impact': 'Neutral',
            'detail': (
                f'Only {headers_score:.0f}% of recommended headers are present. '
                f'Missing: {", ".join(missing_headers[:3])}{"..." if len(missing_headers) > 3 else ""}. '
                'Improving header coverage strengthens the overall security posture alongside PQC migration.'
            ),
        })
    else:
        factors.append({
            'factor': f'Security headers poorly configured ({headers_score:.0f}% coverage)',
            'impact': 'Negative',
            'detail': (
                f'Only {headers_score:.0f}% of recommended headers are present. '
                'Missing HSTS in particular allows TLS downgrade attacks that could expose '
                'encrypted traffic to future quantum decryption.'
            ),
        })

    if dnssec:
        factors.append({
            'factor': 'DNSSEC active — DNS integrity protected',
            'impact': 'Positive',
            'detail': (
                'DNSSEC prevents DNS spoofing attacks that could redirect users to attacker infrastructure, '
                'bypassing TLS entirely. Note: DNSSEC keys themselves (typically RSA/ECDSA) also require '
                'post-quantum migration as a future step.'
            ),
        })
    else:
        factors.append({
            'factor': 'DNSSEC not detected — DNS integrity unprotected',
            'impact': 'Negative',
            'detail': (
                'Without DNSSEC, an attacker can poison DNS responses to redirect traffic, '
                'making even quantum-resistant TLS ineffective. Enabling DNSSEC is complementary to PQC migration.'
            ),
        })

    reasoning = _build_decision_reasoning(profile, migration_priority, factors)

    return {
        'factors': factors,
        'migration_priority': migration_priority,
        'reasoning': reasoning,
        'positive_count': sum(1 for f in factors if f['impact'] == 'Positive'),
        'negative_count': sum(1 for f in factors if f['impact'] == 'Negative'),
    }


def _build_decision_reasoning(profile, migration_priority, factors):
    algorithm = profile.get('algorithm', 'Unknown')
    ssl_version = profile.get('ssl_version', '')
    hybrid_pqc = profile.get('hybrid_pqc', False)
    is_pqc_algo = profile.get('is_pqc_algo', False)
    headers_score = profile.get('headers_score', 0)
    key_exchange = profile.get('key_exchange', 'Unknown')

    negatives = [f['factor'] for f in factors if f['impact'] == 'Negative']
    positives = [f['factor'] for f in factors if f['impact'] == 'Positive']

    if migration_priority == 'Critical':
        return (
            f'Migration priority was set to CRITICAL because one or more conditions that require immediate '
            f'action were detected: {"; ".join(negatives[:2])}. These issues present active risk today, '
            'independent of quantum computing timelines, and must be resolved before any PQC migration can begin.'
        )
    elif migration_priority == 'Low':
        return (
            f'Migration priority was set to LOW because this configuration demonstrates strong quantum readiness: '
            f'{"; ".join(positives[:2])}. '
            'The remaining recommendation is to monitor NIST algorithm updates and maintain cryptographic agility '
            'for future transitions as the PQC ecosystem matures.'
        )
    elif migration_priority == 'Medium':
        return (
            f'Migration priority was set to MEDIUM because the configuration has a solid baseline '
            f'({"; ".join(positives[:1])}) but still uses {algorithm} which is quantum-vulnerable. '
            f'The well-configured environment ({ssl_version}, headers at {headers_score:.0f}%) supports '
            'a phased migration without operational disruption.'
        )
    else:
        return (
            f'Migration priority was set to HIGH because {algorithm} is quantum-vulnerable and no hybrid '
            f'PQC mitigations are in place. '
            f'{"TLS 1.3 is available which enables hybrid ML-KEM key exchange without breaking changes. " if ssl_version == "TLSv1.3" else ""}'
            f'Key negative factors: {"; ".join(negatives[:2])}.'
        )


def _get_impact_label(contribution):
    if contribution >= 0.20:
        return 'Very High'
    elif contribution >= 0.12:
        return 'High'
    elif contribution >= 0.06:
        return 'Medium'
    elif contribution >= 0.02:
        return 'Low'
    else:
        return 'Minimal'


def _generate_summary(contributions, risk_level):
    top = contributions[0] if contributions else None
    if not top:
        return 'Unable to generate explanation.'

    level_descriptions = {
        'Critical': 'This domain has critical quantum security vulnerabilities requiring immediate attention.',
        'High': 'This domain has significant quantum security risks that should be addressed soon.',
        'Medium': 'This domain has moderate quantum security risks and would benefit from improvements.',
        'Low': 'This domain has relatively low quantum security risk but can still be improved.',
    }

    base = level_descriptions.get(risk_level, 'Risk assessment complete.')
    detail = f' The primary risk driver is "{top["feature"]}" ({top["description"]})'
    return base + detail

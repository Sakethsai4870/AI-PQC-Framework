from pqc.quantum import NIST_PQC_STANDARDS, HYBRID_APPROACHES, assess_quantum_risk


def generate_recommendations(ssl_data, domain_data, header_data, features):
    recommendations = []
    priority_actions = []

    algorithm = ssl_data.get('key_algorithm', 'Unknown')
    key_size = ssl_data.get('key_size', 0)
    ssl_version = ssl_data.get('ssl_version', '')

    quantum_risk = assess_quantum_risk(algorithm, key_size, ssl_version)

    if quantum_risk['vulnerable']:
        priority_actions.append({
            'priority': 'Critical',
            'action': f'Migrate from {algorithm} to post-quantum cryptography',
            'detail': (
                f'Your current key algorithm ({algorithm} {key_size}-bit) is vulnerable to quantum attacks. '
                f'{quantum_risk["threat_description"]} '
                f'Begin planning migration to NIST-approved post-quantum algorithms.'
            ),
            'standards': list(NIST_PQC_STANDARDS.keys()),
        })

        recommendations.append({
            'category': 'Key Exchange',
            'recommendation': 'Adopt ML-KEM (KYBER) for key encapsulation',
            'detail': NIST_PQC_STANDARDS['ML-KEM']['description'],
            'standard': 'NIST FIPS 203',
            'urgency': 'High',
        })

        recommendations.append({
            'category': 'Digital Signatures',
            'recommendation': 'Adopt ML-DSA (DILITHIUM) for digital signatures',
            'detail': NIST_PQC_STANDARDS['ML-DSA']['description'],
            'standard': 'NIST FIPS 204',
            'urgency': 'High',
        })

        recommendations.append({
            'category': 'Transition Strategy',
            'recommendation': 'Implement hybrid cryptography as an interim measure',
            'detail': (
                'Use hybrid schemes combining classical and post-quantum algorithms to maintain '
                'compatibility while gaining quantum resistance: ' +
                HYBRID_APPROACHES[0]['name']
            ),
            'standard': 'IETF draft-ietf-tls-hybrid-design',
            'urgency': 'Medium',
        })

    if ssl_version in ('TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3'):
        priority_actions.append({
            'priority': 'Critical',
            'action': f'Upgrade TLS protocol from {ssl_version} to TLS 1.3',
            'detail': (
                f'{ssl_version} is deprecated and vulnerable to multiple attacks (BEAST, POODLE, etc.). '
                'Upgrade to TLS 1.3 immediately for both classical and quantum security.'
            ),
        })
    elif ssl_version == 'TLSv1.2':
        recommendations.append({
            'category': 'Protocol',
            'recommendation': 'Upgrade from TLS 1.2 to TLS 1.3',
            'detail': 'TLS 1.3 offers improved security, forward secrecy, and better performance.',
            'standard': 'RFC 8446',
            'urgency': 'Medium',
        })

    if algorithm == 'RSA' and key_size and key_size < 2048:
        priority_actions.append({
            'priority': 'Critical',
            'action': f'Replace {key_size}-bit RSA key immediately',
            'detail': f'RSA-{key_size} is below the minimum recommended key size of 2048 bits and is considered broken.',
        })

    missing_headers = header_data.get('missing', [])
    if missing_headers:
        recommendations.append({
            'category': 'HTTP Security Headers',
            'recommendation': f'Add missing security headers: {", ".join(missing_headers)}',
            'detail': (
                'Security headers protect against common web attacks. '
                'Missing: ' + ', '.join(missing_headers)
            ),
            'standard': 'OWASP Secure Headers Project',
            'urgency': 'Medium' if len(missing_headers) > 3 else 'Low',
        })

    if not domain_data.get('dnssec_enabled'):
        recommendations.append({
            'category': 'DNS Security',
            'recommendation': 'Enable DNSSEC',
            'detail': (
                'DNSSEC adds cryptographic authentication to DNS responses, preventing DNS spoofing. '
                'Ensure DNSSEC keys also plan for post-quantum migration.'
            ),
            'standard': 'RFC 4033',
            'urgency': 'Medium',
        })

    recommendations.append({
        'category': 'Crypto Agility',
        'recommendation': 'Implement cryptographic agility in your systems',
        'detail': (
            'Design systems to easily swap cryptographic algorithms without major refactoring. '
            'This enables smooth migration as PQC standards mature and hardware support improves.'
        ),
        'urgency': 'Low',
    })

    recommendations.append({
        'category': 'Inventory',
        'recommendation': 'Conduct a full cryptographic inventory',
        'detail': (
            'Identify all places where asymmetric cryptography is used in your infrastructure '
            '(APIs, internal services, code signing, email) to plan a comprehensive PQC migration.'
        ),
        'urgency': 'Medium',
    })

    return {
        'priority_actions': priority_actions,
        'recommendations': recommendations,
        'pqc_standards': NIST_PQC_STANDARDS,
        'hybrid_approaches': HYBRID_APPROACHES,
    }

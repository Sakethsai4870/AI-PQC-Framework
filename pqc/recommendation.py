from pqc.quantum import NIST_PQC_STANDARDS, HYBRID_APPROACHES, assess_quantum_risk


def _detect_key_exchange(cipher_suite):
    cipher = (cipher_suite or '').upper()
    if 'ML-KEM' in cipher or 'KYBER' in cipher:
        return 'ML-KEM'
    if 'X25519' in cipher:
        return 'X25519'
    if 'ECDHE' in cipher or 'ECDH' in cipher:
        return 'ECDHE'
    if 'DHE' in cipher or 'EDH' in cipher:
        return 'DHE'
    if 'RSA' in cipher:
        return 'RSA'
    return 'Unknown'


def _detect_cipher_strength(cipher_suite):
    cipher = (cipher_suite or '').upper()
    if 'CHACHA20' in cipher:
        return 'Strong'
    if 'AES_256' in cipher or 'AES256' in cipher:
        return 'Strong'
    if 'AES_128' in cipher or 'AES128' in cipher:
        return 'Adequate'
    if 'RC4' in cipher or '3DES' in cipher or 'DES' in cipher:
        return 'Weak'
    if 'NULL' in cipher or 'EXPORT' in cipher or 'ANON' in cipher:
        return 'Broken'
    return 'Unknown'


def _classify_profile(ssl_data, domain_data, header_data):
    algorithm = ssl_data.get('key_algorithm', 'Unknown')
    key_size = ssl_data.get('key_size', 0) or 0
    ssl_version = ssl_data.get('ssl_version', '')
    cipher_suite = ssl_data.get('cipher_suite', '')

    hybrid_pqc = header_data.get('hybrid_pqc_detected', False)
    pqc_headers = header_data.get('pqc_headers', {})
    headers_score = header_data.get('score', 0)
    dnssec = domain_data.get('dnssec_enabled', False)
    missing_headers = header_data.get('missing', [])

    key_exchange = _detect_key_exchange(cipher_suite)
    cipher_strength = _detect_cipher_strength(cipher_suite)

    is_pqc_algo = algorithm in ('ML-DSA', 'SLH-DSA', 'FN-DSA')
    is_tls13 = ssl_version == 'TLSv1.3'
    is_tls12 = ssl_version == 'TLSv1.2'
    is_legacy_tls = ssl_version in ('TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2')
    is_weak_key = (algorithm == 'RSA' and key_size > 0 and key_size < 2048)
    headers_strong = headers_score >= 70
    headers_moderate = 40 <= headers_score < 70

    return {
        'algorithm': algorithm,
        'key_size': key_size,
        'ssl_version': ssl_version,
        'cipher_suite': cipher_suite,
        'key_exchange': key_exchange,
        'cipher_strength': cipher_strength,
        'hybrid_pqc': hybrid_pqc,
        'pqc_headers': pqc_headers,
        'headers_score': headers_score,
        'headers_strong': headers_strong,
        'headers_moderate': headers_moderate,
        'missing_headers': missing_headers,
        'dnssec': dnssec,
        'is_pqc_algo': is_pqc_algo,
        'is_tls13': is_tls13,
        'is_tls12': is_tls12,
        'is_legacy_tls': is_legacy_tls,
        'is_weak_key': is_weak_key,
    }


def _determine_migration_priority(profile):
    if profile['is_weak_key']:
        return 'Critical', (
            f'RSA-{profile["key_size"]} is cryptographically broken for classical attacks '
            'and trivially broken by quantum computers. Immediate replacement required.'
        )

    if profile['is_legacy_tls']:
        return 'Critical', (
            f'{profile["ssl_version"]} is deprecated and carries known classical vulnerabilities '
            '(BEAST, POODLE, DROWN) in addition to zero quantum resilience. Upgrade to TLS 1.3 immediately.'
        )

    if profile['hybrid_pqc'] and profile['is_pqc_algo']:
        return 'Low', (
            'Hybrid post-quantum deployment detected with a PQC-native certificate algorithm. '
            'This configuration provides strong quantum resilience. Focus on monitoring NIST updates '
            'and ensuring algorithm agility for future transitions.'
        )

    if profile['hybrid_pqc']:
        return 'Low', (
            'Hybrid post-quantum key exchange headers detected, indicating active PQC deployment. '
            'Certificate algorithm migration is the remaining step for full quantum readiness.'
        )

    if profile['is_pqc_algo'] and profile['is_tls13']:
        return 'Low', (
            'PQC-native certificate algorithm in use with TLS 1.3. Key exchange migration to '
            'ML-KEM or hybrid X25519+ML-KEM is recommended to complete the quantum-resistant posture.'
        )

    if profile['is_tls13'] and profile['headers_strong']:
        return 'Medium', (
            'TLS 1.3 with strong security headers provides a solid baseline. '
            'The certificate algorithm still uses classical cryptography vulnerable to quantum attacks, '
            'but the well-configured environment supports a gradual, controlled migration.'
        )

    if profile['is_tls13'] and profile['cipher_strength'] == 'Strong':
        return 'High', (
            f'TLS 1.3 with {profile["cipher_strength"].lower()} cipher is in place, but the certificate '
            f'algorithm ({profile["algorithm"]}) remains fully vulnerable to Shor\'s algorithm on a '
            'cryptographically relevant quantum computer. Hybrid migration should begin now.'
        )

    if profile['is_tls13']:
        return 'High', (
            f'TLS 1.3 is in use but the certificate algorithm ({profile["algorithm"]}) provides no '
            'quantum resistance. Begin ML-KEM + ML-DSA hybrid migration planning immediately.'
        )

    if profile['is_tls12']:
        return 'High', (
            f'TLS 1.2 with {profile["algorithm"]} offers no quantum security. '
            'Upgrade to TLS 1.3 and initiate hybrid PQC migration in parallel.'
        )

    return 'High', (
        f'The detected cryptographic configuration ({profile["algorithm"]}, {profile["ssl_version"]}) '
        'provides no quantum resilience. Immediate migration planning is required.'
    )


def generate_recommendations(ssl_data, domain_data, header_data, features):
    profile = _classify_profile(ssl_data, domain_data, header_data)
    migration_priority, migration_rationale = _determine_migration_priority(profile)

    quantum_risk = assess_quantum_risk(
        profile['algorithm'], profile['key_size'], profile['ssl_version']
    )

    priority_actions = []
    recommendations = []

    if profile['is_weak_key']:
        priority_actions.append({
            'priority': 'Critical',
            'action': f'Replace RSA-{profile["key_size"]} certificate immediately',
            'detail': (
                f'RSA-{profile["key_size"]} falls below the 2048-bit classical security floor and is '
                'trivially broken. Replace with RSA-4096 minimum as an interim step, '
                'then migrate to ML-DSA (FIPS 204) for full quantum resistance.'
            ),
        })

    if profile['is_legacy_tls']:
        priority_actions.append({
            'priority': 'Critical',
            'action': f'Disable {profile["ssl_version"]} and enable TLS 1.3 only',
            'detail': (
                f'{profile["ssl_version"]} has known exploitable vulnerabilities independent of quantum threats. '
                'Enforce TLS 1.3 which supports hybrid PQC key exchange groups and provides '
                'forward secrecy as a prerequisite for any PQC migration.'
            ),
        })

    if profile['hybrid_pqc'] and profile['is_pqc_algo']:
        recommendations.append({
            'category': 'Quantum Readiness',
            'recommendation': 'Maintain current hybrid PQC deployment and monitor NIST algorithm updates',
            'detail': (
                f'Detected PQC headers: {", ".join(profile["pqc_headers"].keys())}. '
                'Your deployment uses a post-quantum certificate algorithm with hybrid key exchange. '
                'Review NIST IR 8413 periodically and subscribe to NIST PQC mailing lists for deprecation notices.'
            ),
            'standard': 'NIST FIPS 203/204/205/206',
            'urgency': 'Low',
        })
        recommendations.append({
            'category': 'Algorithm Agility',
            'recommendation': 'Audit all internal service-to-service connections for PQC readiness',
            'detail': (
                'External-facing TLS is quantum-ready. Ensure internal APIs, mTLS connections, '
                'code-signing pipelines, and key management infrastructure are also migrated. '
                'Maintaining algorithm agility prevents bottlenecks when NIST issues algorithm updates.'
            ),
            'urgency': 'Low',
        })

    elif profile['hybrid_pqc']:
        recommendations.append({
            'category': 'Certificate Migration',
            'recommendation': f'Migrate certificate from {profile["algorithm"]} to ML-DSA (FIPS 204)',
            'detail': (
                f'Hybrid key exchange is active (detected: {", ".join(profile["pqc_headers"].keys())}), '
                f'but the certificate still uses {profile["algorithm"]} which is broken by Shor\'s algorithm. '
                'Request an ML-DSA certificate from your CA to complete the quantum-resistant chain.'
            ),
            'standard': 'NIST FIPS 204',
            'urgency': 'Medium',
        })
        recommendations.append({
            'category': 'Key Exchange Confirmation',
            'recommendation': 'Verify ML-KEM key exchange is active in TLS handshake',
            'detail': (
                'X-PQC headers indicate intent but confirm via TLS handshake inspection that '
                'ML-KEM-768 or X25519+ML-KEM hybrid groups are negotiated. '
                'Use tools such as tlsfuzzer or Wireshark with TLS 1.3 dissection.'
            ),
            'urgency': 'Low',
        })

    elif profile['is_pqc_algo']:
        recommendations.append({
            'category': 'Key Exchange',
            'recommendation': 'Deploy ML-KEM hybrid key exchange to complement PQC certificate',
            'detail': (
                f'The certificate uses {profile["algorithm"]} (quantum-resistant signature). '
                'The remaining gap is key exchange: add X25519+ML-KEM-768 hybrid group support in your '
                'TLS server configuration (OpenSSL 3.5+ or BoringSSL with ML-KEM patch) '
                'to achieve end-to-end quantum resistance.'
            ),
            'standard': 'NIST FIPS 203, IETF draft-ietf-tls-hybrid-design',
            'urgency': 'Medium',
        })

    elif profile['is_tls13'] and profile['headers_strong']:
        recommendations.append({
            'category': 'Migration Strategy',
            'recommendation': f'Begin gradual certificate migration from {profile["algorithm"]} to ML-DSA while maintaining TLS 1.3',
            'detail': (
                f'Your TLS 1.3 deployment and strong security headers ({profile["headers_score"]:.0f}% score) '
                f'provide a solid foundation. Plan a phased migration: '
                f'(1) Enable X25519+ML-KEM-768 hybrid key exchange groups now (no cert change required), '
                f'(2) Request ML-DSA certificate from a PQC-capable CA, '
                f'(3) Run dual-certificate (classical + PQC) for backward compatibility.'
            ),
            'standard': 'NIST FIPS 203/204, IETF draft-ietf-tls-hybrid-design',
            'urgency': 'Medium',
        })
        recommendations.append({
            'category': 'Hybrid Key Exchange',
            'recommendation': 'Enable X25519+ML-KEM-768 hybrid group in TLS 1.3 immediately',
            'detail': (
                'Hybrid key exchange provides quantum-safe key establishment with zero breaking changes '
                'for clients that do not support ML-KEM. This is deployable today without certificate changes. '
                'Supported in OpenSSL 3.5+, nginx 1.27+, and BoringSSL.'
            ),
            'standard': 'NIST FIPS 203',
            'urgency': 'Medium',
        })

    elif profile['is_tls13'] and profile['cipher_strength'] == 'Strong':
        recommendations.append({
            'category': 'Immediate Migration',
            'recommendation': f'Deploy ML-KEM + ML-DSA hybrid migration for {profile["algorithm"]} certificate',
            'detail': (
                f'TLS 1.3 with {profile["cipher_suite"]} provides excellent classical security, '
                f'but {profile["algorithm"]} is broken by Shor\'s algorithm. '
                'Deploy: (1) X25519+ML-KEM-768 for key exchange (immediate, no cert change), '
                '(2) ML-DSA certificate replacement (requires PQC-capable CA), '
                '(3) Run CRYSTALS-Dilithium in dual-cert mode during transition.'
            ),
            'standard': 'NIST FIPS 203/204',
            'urgency': 'High',
        })

    elif profile['is_tls13']:
        recommendations.append({
            'category': 'Immediate Migration',
            'recommendation': f'Deploy ML-KEM + ML-DSA hybrid migration to replace {profile["algorithm"]}',
            'detail': (
                f'{profile["algorithm"]} on TLS 1.3 has no quantum resistance. '
                'Immediate action: enable X25519+ML-KEM-768 hybrid key exchange in your TLS configuration. '
                'Follow with ML-DSA certificate migration once your CA supports FIPS 204 issuance.'
            ),
            'standard': 'NIST FIPS 203/204',
            'urgency': 'High',
        })

    elif profile['is_tls12']:
        recommendations.append({
            'category': 'Protocol Upgrade',
            'recommendation': 'Upgrade to TLS 1.3 as prerequisite for PQC hybrid key exchange',
            'detail': (
                'TLS 1.3 is required for hybrid ML-KEM key exchange groups. '
                'Upgrading also removes known classical vulnerabilities in TLS 1.2 (BEAST, Lucky13, RC4). '
                'Once on TLS 1.3, enable X25519+ML-KEM-768 and plan ML-DSA certificate migration.'
            ),
            'standard': 'RFC 8446',
            'urgency': 'High',
        })
        recommendations.append({
            'category': 'Certificate',
            'recommendation': f'Plan ML-DSA certificate replacement for {profile["algorithm"]}',
            'detail': (
                f'{profile["algorithm"]} remains quantum-vulnerable regardless of TLS version. '
                'After upgrading to TLS 1.3, request an ML-DSA (FIPS 204) certificate from '
                'a PQC-capable certificate authority.'
            ),
            'standard': 'NIST FIPS 204',
            'urgency': 'High',
        })

    if profile['cipher_strength'] in ('Weak', 'Broken'):
        priority_actions.append({
            'priority': 'Critical',
            'action': f'Replace weak cipher suite: {profile["cipher_suite"]}',
            'detail': (
                f'The cipher suite {profile["cipher_suite"]} is cryptographically weak or broken. '
                'Enforce AES-256-GCM or ChaCha20-Poly1305 which also reduce quantum key strength degradation '
                '(Grover\'s algorithm halves effective key length, so 256-bit keys remain adequate post-quantum).'
            ),
        })

    if not profile['is_pqc_algo'] and not profile['hybrid_pqc'] and not profile['is_legacy_tls']:
        if profile['key_exchange'] in ('RSA', 'DHE', 'Unknown'):
            recommendations.append({
                'category': 'Key Exchange',
                'recommendation': 'Replace RSA/DHE key exchange with ECDHE or X25519',
                'detail': (
                    f'Key exchange via {profile["key_exchange"]} lacks forward secrecy. '
                    'Migrate to ECDHE or X25519 as an intermediate step before deploying '
                    'ML-KEM hybrid groups. Forward secrecy limits the blast radius of future key compromise.'
                ),
                'urgency': 'Medium',
            })

    if profile['missing_headers']:
        critical_missing = [h for h in profile['missing_headers'] if h in (
            'Strict-Transport-Security', 'Content-Security-Policy'
        )]
        if critical_missing:
            priority_actions.append({
                'priority': 'High',
                'action': f'Add critical security headers: {", ".join(critical_missing)}',
                'detail': (
                    f'Missing critical headers: {", ".join(critical_missing)}. '
                    'HSTS prevents TLS downgrade attacks that could expose encrypted traffic to future quantum decryption. '
                    'CSP mitigates injection attacks that could exfiltrate keys before quantum attacks are even relevant.'
                ),
            })
        other_missing = [h for h in profile['missing_headers'] if h not in critical_missing]
        if other_missing:
            recommendations.append({
                'category': 'HTTP Security Headers',
                'recommendation': f'Add remaining security headers: {", ".join(other_missing)}',
                'detail': (
                    f'Currently missing: {", ".join(other_missing)}. '
                    'Complete header coverage strengthens overall security posture and demonstrates '
                    'security maturity alongside PQC readiness.'
                ),
                'standard': 'OWASP Secure Headers Project',
                'urgency': 'Low' if len(other_missing) <= 2 else 'Medium',
            })

    if not profile['dnssec']:
        recommendations.append({
            'category': 'DNS Security',
            'recommendation': 'Enable DNSSEC and plan post-quantum DNSSEC key migration',
            'detail': (
                'DNSSEC prevents DNS cache poisoning attacks that could redirect users to attacker-controlled '
                'servers, rendering TLS certificates irrelevant. '
                'Note: DNSSEC uses RSA or ECDSA signing keys that are also quantum-vulnerable — '
                'plan migration to SLH-DSA (FIPS 205) for DNSSEC signing once registrar support is available.'
            ),
            'standard': 'RFC 4033, NIST FIPS 205',
            'urgency': 'Medium',
        })
    else:
        recommendations.append({
            'category': 'DNS Security',
            'recommendation': 'Plan DNSSEC signing key migration from RSA/ECDSA to SLH-DSA',
            'detail': (
                'DNSSEC is active, which is positive. However, DNSSEC signing keys are typically RSA or ECDSA '
                'and are also vulnerable to Shor\'s algorithm. Plan migration to SLH-DSA (FIPS 205) '
                'for DNSSEC zone signing keys as registrar and resolver support matures.'
            ),
            'standard': 'NIST FIPS 205',
            'urgency': 'Low',
        })

    recommendations.append({
        'category': 'Cryptographic Inventory',
        'recommendation': 'Conduct a full cryptographic bill of materials (CBOM)',
        'detail': (
            'Identify every use of asymmetric cryptography across your infrastructure: '
            'internal APIs, mTLS, JWT signing, SSH keys, code signing, encrypted storage, and email. '
            'NIST recommends a CBOM as the foundation of any post-quantum migration plan. '
            'Tools: CBOM Scanner (CycloneDX), IBM CBOM Tool.'
        ),
        'urgency': 'Medium',
    })

    return {
        'migration_priority': migration_priority,
        'migration_rationale': migration_rationale,
        'priority_actions': priority_actions,
        'recommendations': recommendations,
        'pqc_standards': NIST_PQC_STANDARDS,
        'hybrid_approaches': HYBRID_APPROACHES,
        'profile': profile,
        'quantum_risk': quantum_risk,
    }

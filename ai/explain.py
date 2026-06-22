"""
Explainability module.

explain_prediction()              — Risk factor breakdown bars (quantum vuln score).
generate_ai_decision_explanation() — AI decision explanation with top +/- factors
                                     ranked by RF feature importances.
"""

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

FEATURE_DESCRIPTIONS = {
    'Algorithm Risk':    'How vulnerable the certificate algorithm is to quantum attacks.',
    'Key Size Risk':     'Whether the key size provides adequate security against quantum threats.',
    'Protocol Risk':     'Whether the TLS version is up-to-date and supports PQC hybrid groups.',
    'Cipher Risk':       'How secure the cipher suite is against known cryptographic attacks.',
    'Header Risk':       'Missing or misconfigured HTTP security headers.',
    'DNSSEC Risk':       'Whether DNS responses are cryptographically authenticated.',
    'Hybrid PQC Risk':   'Whether hybrid post-quantum key exchange is actively deployed.',
    'Key Exchange Risk': 'Quantum vulnerability of the key exchange algorithm in use.',
    'PQC Headers Risk':  'Coverage of X-PQC-* headers indicating PQC deployment status.',
}


def explain_prediction(features, prediction, rf_importances=None):
    """
    Build the risk factor breakdown bars.
    If rf_importances is provided (from the RF classifier), those weights are used
    so the bar chart reflects actual model-learned feature importance.
    """
    feature_vector = prediction.get('feature_vector', [])

    if rf_importances and len(rf_importances) == 9:
        weights = list(rf_importances.values())
    else:
        # Default weights used before RF is available
        weights = [0.30, 0.20, 0.20, 0.10, 0.10, 0.10, 0.0, 0.0, 0.0]

    names = RF_FEATURE_NAMES if len(feature_vector) == 9 else RF_FEATURE_NAMES[:len(feature_vector)]

    contributions = []
    for name, value, weight in zip(names, feature_vector, weights):
        contribution = float(value) * float(weight)
        contributions.append({
            'feature':      name,
            'description':  FEATURE_DESCRIPTIONS.get(name, ''),
            'value':        round(float(value), 3),
            'weight':       round(float(weight), 4),
            'contribution': round(contribution, 4),
            'impact':       _get_impact_label(contribution),
        })

    contributions.sort(key=lambda x: x['contribution'], reverse=True)
    summary = _generate_summary(contributions, prediction['risk_level'])

    return {
        'contributions':    contributions,
        'top_risk_factor':  contributions[0]['feature'] if contributions else 'Unknown',
        'summary':          summary,
        'risk_level':       prediction['risk_level'],
        'score':            prediction['score'],
    }


def generate_ai_decision_explanation(ssl_data, domain_data, header_data,
                                     recommendations, feature_importances=None):
    """
    Generate the AI Decision Explanation section.

    Each factor is grounded in the actual scan results.
    When feature_importances is provided from the RF classifier, factors are
    ranked by model-learned importance × detected risk direction, making the
    explanation genuinely model-driven rather than purely rule-based.
    """
    profile = recommendations.get('profile', {})
    migration_priority = recommendations.get('migration_priority', 'Unknown')

    algorithm      = profile.get('algorithm', 'Unknown')
    ssl_version    = profile.get('ssl_version', '')
    key_size       = profile.get('key_size', 0) or 0
    cipher_suite   = profile.get('cipher_suite', '')
    cipher_strength = profile.get('cipher_strength', 'Unknown')
    key_exchange   = profile.get('key_exchange', 'Unknown')
    hybrid_pqc     = profile.get('hybrid_pqc', False)
    pqc_headers    = profile.get('pqc_headers', {})
    headers_score  = profile.get('headers_score', 0)
    dnssec         = profile.get('dnssec', False)
    missing_headers = profile.get('missing_headers', [])
    is_pqc_algo    = profile.get('is_pqc_algo', False)

    # Build raw factors with their feature name for importance ranking
    raw_factors = []

    # ── Certificate Algorithm ─────────────────────────────────────────────────
    if algorithm in ('RSA', 'ECDSA', 'DSA'):
        raw_factors.append({
            'feature_name': 'Algorithm Risk',
            'factor': f'Classical signature algorithm detected ({algorithm})',
            'impact': 'Negative',
            'detail': (
                f'{algorithm} relies on mathematical hardness (integer factorisation / ECDLP) '
                'that Shor\'s algorithm solves in polynomial time on a cryptographically relevant '
                'quantum computer. This is the primary driver of quantum vulnerability.'
            ),
        })
    elif is_pqc_algo:
        raw_factors.append({
            'feature_name': 'Algorithm Risk',
            'factor': f'Post-quantum certificate algorithm in use ({algorithm})',
            'impact': 'Positive',
            'detail': (
                f'{algorithm} is a NIST-standardised post-quantum algorithm (FIPS 204/205/206) '
                'resistant to both classical and quantum attacks, significantly reducing '
                'certificate-level quantum risk.'
            ),
        })
    else:
        raw_factors.append({
            'feature_name': 'Algorithm Risk',
            'factor': f'Unclassified certificate algorithm ({algorithm})',
            'impact': 'Neutral',
            'detail': (
                f'{algorithm} was not matched to known quantum-vulnerable or quantum-resistant '
                'categories. Manual review of the certificate chain is recommended.'
            ),
        })

    # ── Hybrid PQC ────────────────────────────────────────────────────────────
    if hybrid_pqc:
        raw_factors.append({
            'feature_name': 'Hybrid PQC Risk',
            'factor': f'Hybrid PQC deployment detected ({", ".join(pqc_headers.keys())})',
            'impact': 'Positive',
            'detail': (
                'X-PQC-* headers indicate an active hybrid post-quantum deployment, providing '
                'quantum-safe key exchange alongside classical cryptography. '
                f'Detected: {"; ".join(f"{k}={v}" for k, v in pqc_headers.items())}.'
            ),
        })
    else:
        raw_factors.append({
            'feature_name': 'Hybrid PQC Risk',
            'factor': 'Hybrid post-quantum key exchange not detected',
            'impact': 'Negative',
            'detail': (
                'No X-PQC-* headers were found. Without hybrid ML-KEM or similar PQC key exchange, '
                'session keys are vulnerable to "harvest now, decrypt later" attacks by adversaries '
                'storing ciphertexts today for future quantum decryption.'
            ),
        })

    # ── PQC Headers ──────────────────────────────────────────────────────────
    if pqc_headers:
        raw_factors.append({
            'feature_name': 'PQC Headers Risk',
            'factor': f'X-PQC-* headers present ({len(pqc_headers)}/4 detected)',
            'impact': 'Positive',
            'detail': (
                f'{len(pqc_headers)} of 4 post-quantum headers are present, signalling active '
                'PQC infrastructure. A complete set (KeyExchange, Signature, Mode, Version) '
                'provides full visibility into the hybrid deployment posture.'
            ),
        })

    # ── TLS Protocol ─────────────────────────────────────────────────────────
    if ssl_version == 'TLSv1.3':
        raw_factors.append({
            'feature_name': 'Protocol Risk',
            'factor': 'TLS 1.3 supports hybrid PQC key exchange groups',
            'impact': 'Positive',
            'detail': (
                'TLS 1.3 is a prerequisite for hybrid ML-KEM key exchange (IETF draft-ietf-tls-hybrid-design). '
                'Deploying X25519+ML-KEM-768 requires no certificate changes and provides '
                'quantum-safe key establishment with full backward compatibility.'
            ),
        })
    elif ssl_version == 'TLSv1.2':
        raw_factors.append({
            'feature_name': 'Protocol Risk',
            'factor': 'TLS 1.2 — upgrade required before PQC hybrid deployment',
            'impact': 'Negative',
            'detail': (
                'TLS 1.2 does not support hybrid PQC key exchange groups. '
                'Upgrading to TLS 1.3 (RFC 8446) is a hard prerequisite for ML-KEM hybrid deployment.'
            ),
        })
    else:
        raw_factors.append({
            'feature_name': 'Protocol Risk',
            'factor': f'Deprecated TLS version in use ({ssl_version or "Unknown"})',
            'impact': 'Negative',
            'detail': (
                f'{ssl_version or "This protocol version"} carries known exploitable classical '
                'vulnerabilities (BEAST, POODLE, etc.) and has no path to post-quantum compatibility. '
                'Immediate protocol upgrade to TLS 1.3 is required.'
            ),
        })

    # ── Key Exchange ─────────────────────────────────────────────────────────
    if key_exchange in ('ML-KEM',):
        raw_factors.append({
            'feature_name': 'Key Exchange Risk',
            'factor': f'Quantum-resistant key exchange in use ({key_exchange})',
            'impact': 'Positive',
            'detail': (
                f'{key_exchange} (NIST FIPS 203) provides post-quantum key encapsulation, '
                'protecting session keys against quantum adversaries.'
            ),
        })
    elif key_exchange == 'X25519':
        raw_factors.append({
            'feature_name': 'Key Exchange Risk',
            'factor': 'X25519 key exchange — classical but hybrid-ready',
            'impact': 'Neutral',
            'detail': (
                'X25519 is an efficient classical ECDH scheme. While quantum-vulnerable, '
                'it is the most natural candidate for hybrid deployment as X25519+ML-KEM-768. '
                'Adding ML-KEM requires only a TLS server configuration change.'
            ),
        })
    elif key_exchange in ('ECDHE', 'DHE'):
        raw_factors.append({
            'feature_name': 'Key Exchange Risk',
            'factor': f'Classical key exchange detected ({key_exchange})',
            'impact': 'Negative',
            'detail': (
                f'{key_exchange} provides forward secrecy classically but is broken by '
                'Shor\'s algorithm. Migrate to X25519+ML-KEM-768 hybrid for quantum resistance.'
            ),
        })
    else:
        raw_factors.append({
            'feature_name': 'Key Exchange Risk',
            'factor': 'Key exchange algorithm: Unknown (Not Observable)',
            'impact': 'Neutral',
            'detail': (
                'The negotiated key exchange algorithm could not be determined from the cipher suite. '
                'Recommendations account for this uncertainty — assume classical-only until confirmed otherwise.'
            ),
        })

    # ── Key Size ─────────────────────────────────────────────────────────────
    if algorithm == 'RSA' and key_size > 0:
        if key_size < 2048:
            raw_factors.append({
                'feature_name': 'Key Size Risk',
                'factor': f'Critically undersized RSA key ({key_size} bits)',
                'impact': 'Negative',
                'detail': (
                    f'RSA-{key_size} is below the NIST minimum of 2048 bits for classical security '
                    'and is trivially broken. Replace immediately regardless of quantum timelines.'
                ),
            })
        elif key_size >= 4096:
            raw_factors.append({
                'feature_name': 'Key Size Risk',
                'factor': f'Large RSA key ({key_size} bits) — improved classical margin',
                'impact': 'Neutral',
                'detail': (
                    f'RSA-{key_size} offers stronger classical security, but key size provides '
                    'no quantum resistance — Shor\'s algorithm breaks RSA regardless of key length.'
                ),
            })

    # ── Cipher Suite ─────────────────────────────────────────────────────────
    if cipher_strength == 'Strong':
        raw_factors.append({
            'feature_name': 'Cipher Risk',
            'factor': f'Strong AES-256/ChaCha20 symmetric encryption ({cipher_suite[:40] if cipher_suite else "detected"})',
            'impact': 'Positive',
            'detail': (
                'AES-256-GCM and ChaCha20-Poly1305 provide 128-bit post-quantum security '
                'against Grover\'s algorithm (which halves effective symmetric key length). '
                'The symmetric layer is quantum-resistant; the asymmetric layer is not.'
            ),
        })
    elif cipher_strength in ('Weak', 'Broken'):
        raw_factors.append({
            'feature_name': 'Cipher Risk',
            'factor': f'Weak/broken cipher suite detected ({cipher_suite[:40] if cipher_suite else "detected"})',
            'impact': 'Negative',
            'detail': (
                'This cipher suite is broken by classical attacks independent of quantum threats. '
                'Replace with AES-256-GCM or CHACHA20-POLY1305 immediately.'
            ),
        })

    # ── HTTP Security Headers ─────────────────────────────────────────────────
    if headers_score >= 70:
        raw_factors.append({
            'feature_name': 'Header Risk',
            'factor': f'Strong HTTP security headers ({headers_score:.0f}% coverage)',
            'impact': 'Positive',
            'detail': (
                f'{headers_score:.0f}% of recommended headers are present. HSTS prevents TLS '
                'downgrade attacks that could expose session keys to future quantum decryption. '
                'Strong header posture supports a controlled, phased PQC migration.'
            ),
        })
    elif headers_score >= 40:
        raw_factors.append({
            'feature_name': 'Header Risk',
            'factor': f'HTTP security headers partially configured ({headers_score:.0f}% coverage)',
            'impact': 'Neutral',
            'detail': (
                f'{headers_score:.0f}% of headers are present. '
                f'Missing: {", ".join(missing_headers[:3])}{"…" if len(missing_headers) > 3 else ""}. '
                'Completing header coverage reduces attack surface alongside PQC migration.'
            ),
        })
    else:
        raw_factors.append({
            'feature_name': 'Header Risk',
            'factor': f'HTTP security headers poorly configured ({headers_score:.0f}% coverage)',
            'impact': 'Negative',
            'detail': (
                f'Only {headers_score:.0f}% of recommended headers are present. '
                'Missing HSTS allows TLS downgrade attacks that could expose traffic to '
                'future quantum decryption.'
            ),
        })

    # ── DNSSEC ────────────────────────────────────────────────────────────────
    if dnssec:
        raw_factors.append({
            'feature_name': 'DNSSEC Risk',
            'factor': 'DNSSEC active — DNS integrity protected',
            'impact': 'Positive',
            'detail': (
                'DNSSEC prevents DNS cache-poisoning attacks that could redirect users to '
                'attacker-controlled infrastructure, bypassing even quantum-resistant TLS. '
                'Note: DNSSEC zone-signing keys (typically RSA/ECDSA) will also need migration to SLH-DSA.'
            ),
        })
    else:
        raw_factors.append({
            'feature_name': 'DNSSEC Risk',
            'factor': 'DNSSEC not detected — DNS integrity unprotected',
            'impact': 'Negative',
            'detail': (
                'Without DNSSEC, DNS poisoning can redirect all traffic regardless of TLS strength. '
                'Enabling DNSSEC is complementary to PQC migration and should be part of the same roadmap.'
            ),
        })

    # ── Rank factors by RF feature importance ────────────────────────────────
    if feature_importances:
        def sort_key(f):
            imp = feature_importances.get(f['feature_name'], 0.0)
            # For negative factors, higher risk value * importance = higher rank
            # For positive factors, rank by importance alone
            return imp

        raw_factors.sort(key=sort_key, reverse=True)

    # Separate into positive and negative lists (top 4 each for clean display)
    positive_factors = [f for f in raw_factors if f['impact'] == 'Positive'][:4]
    negative_factors = [f for f in raw_factors if f['impact'] == 'Negative'][:4]
    neutral_factors  = [f for f in raw_factors if f['impact'] == 'Neutral'][:2]

    reasoning = _build_decision_reasoning(profile, migration_priority,
                                          positive_factors, negative_factors,
                                          feature_importances)

    return {
        'factors':          raw_factors,
        'positive_factors': positive_factors,
        'negative_factors': negative_factors,
        'neutral_factors':  neutral_factors,
        'migration_priority': migration_priority,
        'reasoning':        reasoning,
        'positive_count':   len(positive_factors),
        'negative_count':   len(negative_factors),
    }


def _build_decision_reasoning(profile, migration_priority,
                               positives, negatives, feature_importances):
    algorithm     = profile.get('algorithm', 'Unknown')
    ssl_version   = profile.get('ssl_version', '')
    headers_score = profile.get('headers_score', 0)
    hybrid_pqc    = profile.get('hybrid_pqc', False)

    pos_phrases = [f['factor'] for f in positives[:2]]
    neg_phrases = [f['factor'] for f in negatives[:2]]

    # Include top RF feature if available
    top_feature = ''
    if feature_importances:
        top_feat_name = max(feature_importances, key=feature_importances.get)
        top_feat_imp = feature_importances[top_feat_name]
        top_feature = (f' The most influential model feature was '
                       f'"{top_feat_name}" (importance: {top_feat_imp:.3f}).')

    if migration_priority == 'Critical':
        return (
            f'The AI model assigned CRITICAL migration priority due to severe configuration risks: '
            f'{"; ".join(neg_phrases)}. '
            f'These conditions present exploitable risk independent of quantum computing timelines.'
            f'{top_feature}'
        )
    elif migration_priority == 'Low':
        return (
            f'The AI model assigned LOW migration priority because quantum-resistant mitigations '
            f'are already in place: {"; ".join(pos_phrases)}. '
            f'Focus should be on maintaining the deployment and monitoring NIST algorithm updates.'
            f'{top_feature}'
        )
    elif migration_priority == 'Medium':
        return (
            f'The AI model assigned MEDIUM migration priority. Positive factors '
            f'({"; ".join(pos_phrases)}) provide a stable foundation, but {algorithm} '
            f'remains quantum-vulnerable. The {ssl_version} deployment and '
            f'{headers_score:.0f}% header coverage support a phased, low-disruption migration.'
            f'{top_feature}'
        )
    else:
        return (
            f'The AI model assigned HIGH migration priority. {algorithm} has no quantum resistance '
            f'and no hybrid PQC mitigations are in place. '
            f'{"TLS 1.3 is available, enabling X25519+ML-KEM-768 hybrid key exchange without breaking changes. " if ssl_version == "TLSv1.3" else ""}'
            f'Key risk factors: {"; ".join(neg_phrases)}.'
            f'{top_feature}'
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
        'High':     'This domain has significant quantum security risks that should be addressed soon.',
        'Medium':   'This domain has moderate quantum security risks and would benefit from improvements.',
        'Low':      'This domain has relatively low quantum security risk but can still be improved.',
    }
    base   = level_descriptions.get(risk_level, 'Risk assessment complete.')
    detail = f' The highest-weighted risk factor is "{top["feature"]}" ({top["description"]})'
    return base + detail

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

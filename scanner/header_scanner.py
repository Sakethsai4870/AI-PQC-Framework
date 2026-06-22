import requests

SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Referrer-Policy',
    'Permissions-Policy',
    'X-XSS-Protection',
]

PQC_HEADERS = [
    'X-PQC-KeyExchange',
    'X-PQC-Signature',
    'X-PQC-Mode',
    'X-PQC-Version',
]


def scan_headers(domain):
    result = {
        'headers': {},
        'present': [],
        'missing': [],
        'score': 0.0,
        'pqc_headers': {},
        'hybrid_pqc_detected': False,
        'error': None,
    }

    try:
        url = f'https://{domain}'
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={'User-Agent': 'PQC-Framework-Scanner/1.0'},
            verify=False
        )

        headers = dict(response.headers)
        result['headers'] = {k: v for k, v in headers.items()}
        headers_lower = {k.lower(): v for k, v in headers.items()}

        present = []
        missing = []
        for h in SECURITY_HEADERS:
            if h.lower() in headers_lower:
                present.append(h)
            else:
                missing.append(h)

        result['present'] = present
        result['missing'] = missing
        result['score'] = round(len(present) / len(SECURITY_HEADERS) * 100, 1)

        detected_pqc = {}
        for ph in PQC_HEADERS:
            val = headers_lower.get(ph.lower())
            if val:
                detected_pqc[ph] = val
        result['pqc_headers'] = detected_pqc
        result['hybrid_pqc_detected'] = len(detected_pqc) > 0

    except requests.exceptions.SSLError:
        result['error'] = 'SSL certificate verification failed'
        result['score'] = 0.0
    except requests.exceptions.ConnectionError:
        result['error'] = 'Could not connect to host'
        result['score'] = 0.0
    except requests.exceptions.Timeout:
        result['error'] = 'Request timed out'
        result['score'] = 0.0
    except Exception as e:
        result['error'] = str(e)
        result['score'] = 0.0

    return result

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


def scan_headers(domain):
    result = {
        'headers': {},
        'present': [],
        'missing': [],
        'score': 0.0,
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

        present = []
        missing = []
        for h in SECURITY_HEADERS:
            if h.lower() in [k.lower() for k in headers.keys()]:
                present.append(h)
            else:
                missing.append(h)

        result['present'] = present
        result['missing'] = missing
        result['score'] = round(len(present) / len(SECURITY_HEADERS) * 100, 1)

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

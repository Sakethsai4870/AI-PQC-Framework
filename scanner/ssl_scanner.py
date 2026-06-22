import ssl
import socket
from datetime import datetime


def scan_ssl(domain):
    result = {
        'ssl_version': None,
        'cipher_suite': None,
        'key_algorithm': None,
        'key_size': None,
        'cert_expiry': None,
        'cert_subject': None,
        'cert_issuer': None,
        'error': None,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                ssl_info = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                result['ssl_version'] = version
                result['cipher_suite'] = cipher[0] if cipher else 'Unknown'

                if ssl_info:
                    not_after = ssl_info.get('notAfter', '')
                    result['cert_expiry'] = not_after

                    subject = dict(x[0] for x in ssl_info.get('subject', []))
                    issuer = dict(x[0] for x in ssl_info.get('issuer', []))
                    result['cert_subject'] = subject.get('commonName', domain)
                    result['cert_issuer'] = issuer.get('organizationName', 'Unknown')

        cert_der = ssl.get_server_certificate((domain, 443))
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            cert = x509.load_pem_x509_certificate(cert_der.encode(), default_backend())
            pub_key = cert.public_key()
            key_type = type(pub_key).__name__

            if 'RSA' in key_type:
                result['key_algorithm'] = 'RSA'
                result['key_size'] = pub_key.key_size
            elif 'EC' in key_type:
                result['key_algorithm'] = 'ECDSA'
                result['key_size'] = pub_key.key_size
            elif 'DSA' in key_type:
                result['key_algorithm'] = 'DSA'
                result['key_size'] = pub_key.key_size
            else:
                result['key_algorithm'] = key_type
                result['key_size'] = 0
        except Exception:
            result['key_algorithm'] = 'Unknown'
            result['key_size'] = 0

    except ssl.SSLError as e:
        result['error'] = f'SSL Error: {str(e)}'
    except socket.timeout:
        result['error'] = 'Connection timed out'
    except socket.gaierror:
        result['error'] = f'Could not resolve hostname: {domain}'
    except ConnectionRefusedError:
        result['error'] = 'Connection refused (port 443 may not be open)'
    except Exception as e:
        result['error'] = f'Scan error: {str(e)}'

    return result
